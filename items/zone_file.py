from bundlewrap.items import Item, ItemStatus
from bundlewrap.exceptions import BundleError
from bundlewrap.utils.text import force_text, mark_for_translation as _
from bundlewrap.utils.remote import PathInfo
import types
from shlex import quote
from ipaddress import ip_network
import tempfile
import os
import socket
import re
import datetime

try:
    import dns.zone
except ImportError:
    import sys
    sys.stderr.write("Requires dnspython module\nInstall with\n\npip3 install dnspython\n\n"
                     "If you still get this error, try renaming `/usr/local/lib/python3.6/site-packages/DNS` "
                     "to `/usr/local/lib/python3.6/site-packages/dns`. Upper to lowercase")
    sys.exit(1)

from tempfile import NamedTemporaryFile

from dns.rdtypes.ANY.NS import NS
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA
from dns.rdtypes.ANY.CNAME import CNAME
from dns.rdtypes.IN.SRV import SRV
from dns.rdtypes.ANY.PTR import PTR
from dns.rdtypes.ANY.SOA import SOA
from dns.rdtypes.ANY.TXT import TXT

from dns.zone import NoSOA, NoNS

allowed_records = {
    'NS': {
        'class': dns.rdataclass.IN,
        'type': dns.rdatatype.NS,
        'obj': lambda x: NS(dns.rdataclass.IN, dns.rdatatype.NS, to_name(x))
    },
    'A': {
        'class': dns.rdataclass.IN,
        'type': dns.rdatatype.A,
        'obj': lambda x: A(dns.rdataclass.IN, dns.rdatatype.A, x)
    },
    'AAAA': {
        'class': dns.rdataclass.IN,
        'type': dns.rdatatype.AAAA,
        'obj': lambda x: AAAA(dns.rdataclass.IN, dns.rdatatype.AAAA, x)
    },
    'CNAME': {
        'class': dns.rdataclass.IN,
        'type': dns.rdatatype.CNAME,
        'obj': lambda x: CNAME(dns.rdataclass.IN, dns.rdatatype.CNAME, to_name(x))
    },
    'SRV': {
        'class': dns.rdataclass.IN,
        'type': dns.rdatatype.SRV,
        'obj': lambda x: SRV(dns.rdataclass.IN, dns.rdatatype.SRV, x[0], x[1], x[2], to_name(x[3]))
    },
    'PTR': {
        'class': dns.rdataclass.IN,
        'type': dns.rdatatype.PTR,
        'obj': lambda x: PTR(dns.rdataclass.IN, dns.rdatatype.PTR, to_name(x))
    },
    'TXT': {
        'class': dns.rdataclass.IN,
        'type': dns.rdatatype.TXT,
        'obj': lambda x: TXT(dns.rdataclass.IN, dns.rdatatype.TXT, x)
    },
}


def to_name(name):
    return dns.name.Name(name.split('.'))


def add_dot(url):
    if url[-1] != '.':
        url += '.'

    return url


def generate_zone(zone_name, attributes):
    zone = dns.zone.Zone(zone_name)

    serial = int('{0:%y%m%d%H%M}'.format(datetime.datetime.now()))
    mname = attributes['soa']['nameserver']
    rname = attributes['soa']['postmaster']
    refresh = attributes['soa'].get('refresh', 14400)
    retry = attributes['soa'].get('retry', 7200)
    expire = attributes['soa'].get('expire', 604800)
    minimum = attributes['soa'].get('minimum', 14400)

    default_ttl = int(attributes.get('default_ttl', 60))

    root = zone.get_node('@', create=True)
    rdset = root.get_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA, create=True)
    soa = SOA(dns.rdataclass.IN, dns.rdatatype.SOA,
              to_name(mname), to_name(rname), serial, int(refresh), int(retry), int(expire), int(minimum)
              )
    rdset.add(soa, default_ttl)

    for node_name in attributes['records'].keys():
        node = zone.get_node(node_name, create=True)

        for r in attributes['records'][node_name]:
            if r['type'] not in allowed_records.keys():
                continue

            record_type = allowed_records[r['type']]
            rdset = node.get_rdataset(record_type['class'], record_type['type'], create=True)

            record = record_type['obj'](r['value'])
            ttl = r.get('ttl', default_ttl)
            rdset.add(record, ttl)

    return zone


def get_records_from_zone(zone, zone_name):
    records = []

    for node_name in zone:
        node = zone.get_node(str(node_name))
        for r in node:
            if r.match(dns.rdataclass.IN, dns.rdatatype.SOA, dns.rdatatype.NONE):
                # ignore SOA
                continue

            records += [r.to_text(node_name, origin=to_name(zone_name), relativize=True), ]

    return records


def get_soa_from_zone(zone, zone_name):
    _soa_rec = zone[zone_name].get_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
    if not _soa_rec:
        # we have no soa, so create new file
        return None

    return list(_soa_rec)[0]


class ZoneFile(Item):
    """
    Generate BindZoneFiles.
    """
    BUNDLE_ATTRIBUTE_NAME = "zonefiles"
    NEEDS_STATIC = [
        "pkg_apt:",
        "pkg_pacman:",
        "pkg_yum:",
        "pkg_zypper:",
    ]
    ITEM_ATTRIBUTES = {
        'soa': None,
        'records': None,
        'default_ttl': None,
        'zonefile_directory': None,
        'dynamic': None,
    }
    ITEM_TYPE_NAME = "zonefile"
    REQUIRED_ATTRIBUTES = ['soa', 'records']

    def __repr__(self):
        return "<zonefile:{}>".format(self.name)

    def fix(self, status):
        zone_name = add_dot(self.name)
        remote_file_name = '{dir}/{file}.zone'.format(
            dir=self.attributes.get('zonefile_directory', '/var/lib/powerdns/zones'),
            file=self.name
        )
        default_ttl = int(self.attributes.get('default_ttl', 60))

        zone = generate_zone(zone_name, self.attributes)
        # TODO: if dynamic only add missing

        # generate local tmp files
        tmp_file = NamedTemporaryFile(delete=False)
        header = "$ORIGIN {origin}\n$TTL {ttl}\n\n".format(origin=zone_name, ttl=default_ttl)

        tmp_file.write(header.encode('utf-8'))
        zone.to_file(tmp_file)
        tmp_file.close()

        # upload files to node
        self.node.upload(tmp_file.name, remote_file_name, '444', 'root', 'root')

        # remove file
        os.unlink(tmp_file.name)

    # should look like this
    def cdict(self):
        zone_name = add_dot(self.name)
        zone = generate_zone(zone_name, self.attributes)

        soa = get_soa_from_zone(zone, zone_name)
        records = get_records_from_zone(zone, zone_name)

        cdict = {
            'type': 'zonefile',
            'zone_name': zone_name,
            'soa_mname': str(soa.mname),
            'soa_rname': str(soa.rname),
            'soa_refresh': int(soa.refresh),
            'soa_retry': int(soa.retry),
            'soa_expire': int(soa.expire),
            'soa_minimum': int(soa.minimum),
            'records': sorted(records),
        }

        return cdict

    # real world
    def sdict(self):
        zone_name = add_dot(self.name)
        remote_file_name = '{dir}/{file}.zone'.format(
            dir=self.attributes.get('zonefile_directory', '/var/lib/powerdns/zones'),
            file=self.name
        )

        tmp_file = NamedTemporaryFile()

        res = self.node.run('test -f {}'.format(remote_file_name), may_fail=True)
        if res.return_code != 0:
            return None

        self.node.download(remote_file_name, tmp_file.name)
        try:
            zone = dns.zone.from_file(tmp_file.name, zone_name)
        except NoSOA:
            # file cannot be parsed, does not have a SOA
            return None
        except NoNS:
            # file cannot be parsed, does not have a NS
            return None

        tmp_file.close()

        if not zone:
            return None

        soa = get_soa_from_zone(zone, zone_name)
        records = get_records_from_zone(zone, zone_name)

        if not soa or not records:
            return None

        if self.attributes.get('dynamic', False):
            # remove dynamic records
            should_zone_name = add_dot(self.name)
            should_zone = generate_zone(should_zone_name, self.attributes)

            should_records = get_records_from_zone(should_zone, should_zone_name)

            # filder records
            records = [x for x in records if x in should_records]

        sdict = {
            'type': 'zonefile',
            'zone_name': zone_name,
            'soa_mname': str(soa.mname),
            'soa_rname': str(soa.rname),
            'soa_refresh': int(soa.refresh),
            'soa_retry': int(soa.retry),
            'soa_expire': int(soa.expire),
            'soa_minimum': int(soa.minimum),
            'records': sorted(records),
        }

        return sdict

    @classmethod
    def validate_attributes(cls, bundle, item_id, attributes):
        if 'nameserver' not in attributes['soa']:
            raise BundleError(_(
                "no Nameserver in SOA Record found {item} in bundle '{bundle}'"
            ).format(
                bundle=bundle.name,
                item=item_id,
            ))

        if 'postmaster' not in attributes['soa']:
            raise BundleError(_(
                "no Postmaster in SOA Record found {item} in bundle '{bundle}'"
            ).format(
                bundle=bundle.name,
                item=item_id,
            ))

    def patch_attributes(self, attributes):
        if attributes['soa']['nameserver'][-1] != '.':
            attributes['soa']['nameserver'] += '.'

        if attributes['soa']['postmaster'][-1] != '.':
            attributes['soa']['postmaster'] += '.'

        attributes['soa']['postmaster'] = attributes['soa']['postmaster'].replace('@', '.')

        if 'default_ttl' not in attributes:
            attributes['default_ttl'] = 60

        return attributes

    @classmethod
    def get_auto_deps(cls, items):
        deps = []
        for item in items:
            # debian TODO: add other package manager
            if item.ITEM_TYPE_NAME == 'pkg_apt' and item.name == 'powerdns':
                deps.append(item.id)
        return deps
