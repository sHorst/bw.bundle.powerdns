from bundlewrap.items import Item, ItemStatus
from bundlewrap.exceptions import BundleError
from bundlewrap.utils.text import force_text, mark_for_translation as _
from bundlewrap.utils.remote import PathInfo

import os
import base64
from pipes import quote
from tempfile import NamedTemporaryFile

try:
    import dns.zone
except ImportError:
    import sys
    sys.stderr.write("Requires dnspython module\nInstall with\n\npip3 install dnspython\n\n"
                     "If you still get this error, try renaming `/usr/local/lib/python3.6/site-packages/DNS` "
                     "to `/usr/local/lib/python3.6/site-packages/dns`. Upper to lowercase")
    sys.exit(1)

from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.ANY.DS import DS

from dns.rdtypes.dnskeybase import SEP, ZONE, REVOKE
from dns.dnssec import algorithm_to_text, RSASHA256, RSASHA512, RSASHA1


def to_name(name):
    return dns.name.Name(name.split('.'))


def add_dot(url):
    if url[-1] != '.':
        url += '.'

    return url


def parse_zone_info(stdin):
    zone_info = {
        'enabled': True,
    }

    last_key_id = 0
    for line in stdin.split('\n'):
        if line == 'This is a Master zone':
            zone_info['type'] = 'master'
        elif line == 'This is a Slave zone':
            zone_info['type'] = 'slave'
        elif line == 'Zone is not actively secured':
            zone_info['enabled'] = False
        elif line == 'Metadata items: None':
            zone_info['nsec3'] = False
        elif 'Metadata items:' in line:
            zone_info['metadata'] = {}
        elif 'NSEC3PARAM' in line:
            zone_info['metadata']['NSEC3PARAM'] = line.split('NSEC3PARAM', 1)[1].strip()
        elif 'Zone has hashed NSEC3 semantics' in line:
            zone_info['nsec3'] = True
        elif 'Last SOA serial number we notified:' in line:
            nr = line.split(':', 1)[1].split('(', 1)[0]

            last_soa_serial_notified = 0
            last_soa_serial_database = 0
            if '==' in nr:
                (last_soa_serial_notified, last_soa_serial_database) = nr.split('==', 1)
            if '!=' in nr:
                (last_soa_serial_notified, last_soa_serial_database) = nr.split('!=', 1)

            zone_info['last_soa_serial_notified'] = int(last_soa_serial_notified)
            zone_info['last_soa_serial_database'] = int(last_soa_serial_database)

        elif 'No keys for zone ' in line:
            zone_info['keys'] = {}
        elif 'keys:' in line:
            zone_info['keys'] = {}
        elif 'ID = ' in line:
            key = {}
            if 'Active' in line:
                key['active'] = True
                values = line.split('Active', 1)[0].strip()
            else:
                key['active'] = False
                values = line.split('Inactive', 1)[0].strip()

            for tmp in values.split(', '):
                k, v = tmp.split(' = ', 1)
                if k == 'ID':
                    v = v[0:-5]  # remove (ZSK|KSK|CSK) from id
                key[k] = int(v)

            last_key_id = key['ID']
            zone_info['keys'][key['ID']] = key  # This will break if ID is not set, this is on purpose
        elif 'CSK DNSKEY = ' in line:
            tok = dns.tokenizer.Tokenizer(line.split(' = ', 1)[1].split('IN DNSKEY ', 1)[1], '<string>')
            zone_info['keys'][last_key_id]['DNSKEY'] = DNSKEY.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, tok)
        elif 'KSK DNSKEY = ' in line:
            tok = dns.tokenizer.Tokenizer(line.split(' = ', 1)[1].split('IN DNSKEY ', 1)[1], '<string>')
            zone_info['keys'][last_key_id]['DNSKEY'] = DNSKEY.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, tok)
        elif 'DS = ' in line:
            if 'DS' not in zone_info['keys'][last_key_id].keys():
                zone_info['keys'][last_key_id]['DS'] = []

            tok = dns.tokenizer.Tokenizer(line.split(' = ', 1)[1].split('IN DS ', 1)[1], '<string>')
            zone_info['keys'][last_key_id]['DS'] += [DS.from_text(dns.rdataclass.IN, dns.rdatatype.DS, tok), ]

    return zone_info


class ZoneDnssec(Item):
    """
    Generate DNSSec for Zone.
    """

    def preview(self):
        pass

    BUNDLE_ATTRIBUTE_NAME = "zones_dnssec"
    NEEDS_STATIC = [
        "pkg_apt:",
        "pkg_pacman:",
        "pkg_yum:",
        "pkg_zypper:",
    ]
    ITEM_ATTRIBUTES = {
        'keys': None,
        'nsec3': False,
        'disabled': False,
    }
    ITEM_TYPE_NAME = "zone_dnssec"
    REQUIRED_ATTRIBUTES = []

    def __repr__(self):
        return "<zone_dnssec:{}>".format(self.name)

    def upload_key(self, public_key, private_key, active):
        zone_name = add_dot(self.name)
        remote_file_name = '/etc/powerdns/tmp_key.key'

        # generate local tmp files
        tmp_file = NamedTemporaryFile(delete=False)

        tmp_file.write(private_key.encode('utf-8'))
        tmp_file.close()

        # upload files to node
        self.node.upload(tmp_file.name, remote_file_name, '400', 'root', 'root')

        # remove file
        os.unlink(tmp_file.name)

        self.node.run('pdnsutil import-zone-key {zone} {file} {active} ksk'.format(
            zone=zone_name,
            file=remote_file_name,
            active='active' if active else 'inactive',
        ), may_fail=True)

        # remove temp file on node
        self.node.run('rm -f {}'.format(remote_file_name))

        algorithm = algorithm_to_text(public_key.algorithm)

        key_length = ''
        if public_key.algorithm in [RSASHA1, RSASHA256, RSASHA512]:
            key_length = '2048'

        # TODO: add two zsk for the given ksk (check for the correct key length
        self.node.run('pdnsutil add-zone-key {zone} zsk {active} {key_length} {algorithm}'.format(
            zone=zone_name,
            key_length=key_length,
            algorithm=algorithm,
            active='active' if active else 'inactive',
        ), may_fail=True)

        self.node.run('pdnsutil add-zone-key {zone} zsk inactive {key_length} {algorithm}'.format(
            zone=zone_name,
            key_length=key_length,
            algorithm=algorithm,
        ), may_fail=True)

    def delete_key(self, key_id):
        zone_name = add_dot(self.name)

        self.node.run('pdnsutil remove-zone-key {zone} {key_id}'.format(
            zone=zone_name,
            key_id=key_id,
        ), may_fail=True)

        # reload zone
        self.node.run('pdnsutil rectify-zone {zone}'.format(
            zone=zone_name,
        ), may_fail=True)

    def activate_key(self, key_id):
        zone_name = add_dot(self.name)

        self.node.run('pdnsutil activate-zone-key {zone} {key_id}'.format(
            zone=zone_name,
            key_id=key_id,
        ), may_fail=True)

        # reload zone
        self.node.run('pdnsutil rectify-zone {zone}'.format(
            zone=zone_name,
        ), may_fail=True)

    def deactivate_key(self, key_id):
        zone_name = add_dot(self.name)

        self.node.run('pdnsutil deactivate-zone-key {zone} {key_id}'.format(
            zone=zone_name,
            key_id=key_id,
        ), may_fail=True)

        # reload zone
        self.node.run('pdnsutil rectify-zone {zone}'.format(
            zone=zone_name,
        ), may_fail=True)

    def set_nec3(self, param):
        zone_name = add_dot(self.name)
        if param:
            self.node.run('pdnsutil set-nsec3 {zone} {parameter}'.format(
                zone=zone_name,
                parameter=quote(param)
            ), may_fail=True)

            # reload zone
            self.node.run('pdnsutil rectify-zone {zone}'.format(
                zone=zone_name,
            ), may_fail=True)
        else:
            self.node.run('pdnsutil unset-nsec3 {zone}'.format(
                zone=zone_name,
            ), may_fail=True)

    @property
    def keycount(self):
        return len(self.attributes.get('keys', {}).keys())

    def fix(self, status):
        zone_name = add_dot(self.name)

        if status.must_be_deleted:
            # Delete
            self.node.run('pdnsutil disable-dnssec {zone}'.format(
                zone=zone_name,
            ), may_fail=True)

        elif status.must_be_created:
            # Create
            for id, key in self.attributes.get('keys', {}).items():
                public_key = key.get('public_key', {})
                pk = DNSKEY(dns.rdataclass.IN, dns.rdatatype.DNSKEY, SEP | ZONE, 3, public_key.get('algorithm', 8),
                            base64.b64decode(public_key.get('key', '')))

                self.upload_key(pk, key['private_key'], key.get('active', False))

            self.set_nec3(status.cdict['nsec3param'] if status.cdict['nsec3'] else False)
        else:
            res = self.node.run('pdnsutil show-zone {}'.format(zone_name), may_fail=True)
            if res.return_code != 0:
                return None

            zone_info = parse_zone_info(res.stdout.decode('utf-8'))

            if 'pk_keys' in status.keys_to_fix:
                to_install = [x for x in status.cdict['pk_keys'] if x not in status.sdict['pk_keys']]
                to_remove = [x for x in status.sdict['pk_keys'] if x not in status.cdict['pk_keys']]

                for id, key in self.attributes['keys'].items():
                    public_key = key.get('public_key', {})
                    pk = DNSKEY(dns.rdataclass.IN, dns.rdatatype.DNSKEY, SEP | ZONE, 3, public_key.get('algorithm', 8),
                                base64.b64decode(public_key.get('key', '')))

                    if pk.to_text() in to_install:
                        self.upload_key(pk, key['private_key'], key.get('active', False))

                for id, key in zone_info.get('keys', {}).items():
                    if 'DNSKEY' in key.keys():
                        if key['DNSKEY'].to_text() in to_remove:
                            self.delete_key(id)

            if 'active_keys' in status.keys_to_fix:
                to_activate = [x for x in status.cdict['active_keys'] if x not in status.sdict['active_keys']]
                to_deactivate = [x for x in status.sdict['active_keys'] if x not in status.cdict['active_keys']]

                for id, key in zone_info.get('keys', {}).items():
                    if 'DNSKEY' in key.keys():
                        if key['DNSKEY'].to_text() in to_activate:
                            self.activate_key(id)
                        if key['DNSKEY'].to_text() in to_deactivate:
                            self.deactivate_key(id)

            if 'nsec3' in status.keys_to_fix or 'nsec3param' in status.keys_to_fix:
                self.set_nec3(status.cdict['nsec3param'] if status.cdict['nsec3'] else False)

    # should look like this
    def cdict(self):
        zone_name = add_dot(self.name)
        nsec3param = self.attributes.get('nsec3', False)

        # delete the DNSSec
        if self.attributes.get('disabled', False):
            return None

        active_keys = []
        public_keys = []
        for id, key in self.attributes['keys'].items():
            public_key = key.get('public_key', {})
            pk = DNSKEY(dns.rdataclass.IN, dns.rdatatype.DNSKEY, SEP | ZONE, 3, public_key.get('algorithm', 8), base64.b64decode(public_key.get('key', '')))

            public_keys += [pk.to_text(), ]
            if key.get('active', False):
                active_keys += [pk.to_text(), ]

        cdict = {
            'type': 'zone_dnssec',
            'zone_name': zone_name,
            'nsec3': nsec3param is not False,
            'nsec3param': nsec3param if nsec3param is not False else '',
            'active_keys': sorted(active_keys),
            'pk_keys': sorted(public_keys),
        }

        return cdict

    # real world
    def sdict(self):
        zone_name = add_dot(self.name)

        res = self.node.run('pdnsutil show-zone {}'.format(zone_name), may_fail=True)
        if res.return_code != 0:
            return None

        zone_info = parse_zone_info(res.stdout.decode('utf-8'))

        if not zone_info.get('enabled', False):
            return None

        keys = zone_info.get('keys', {})
        sdict = {
            'type': 'zone_dnssec',
            'zone_name': zone_name,
            'nsec3': zone_info.get('nsec3', False),
            'nsec3param': zone_info.get('metadata', {}).get('NSEC3PARAM', ''),
            'active_keys': sorted([y['DNSKEY'].to_text() for (x, y) in keys.items() if 'DNSKEY' in y.keys() and y.get('active', False)]),
            'pk_keys': sorted([y['DNSKEY'].to_text() for (x, y) in keys.items() if 'DNSKEY' in y.keys()]),
        }

        return sdict

    @classmethod
    def validate_attributes(cls, bundle, item_id, attributes):
        if 'disabled' in attributes.keys() and len(attributes.keys()) > 1:
            raise BundleError(_(
                "disabled cannot coexist with other Attributes for {item} in bundle '{bundle}'"
            ).format(
                bundle=bundle.name,
                item=item_id,
            ))

        if not attributes.get('disabled', False):
            if 'keys' not in attributes.keys() or not isinstance(attributes['keys'], dict):
                raise BundleError(_(
                    "keys is not set as DICT for {item} in bundle '{bundle}'"
                ).format(
                    bundle=bundle.name,
                    item=item_id,
                ))

            active_keys = [x for (x, y) in attributes['keys'].items() if y.get('active', False)]
            if len(active_keys) < 1:
                raise BundleError(_(
                    "at least one key needs to beactive for {item} in bundle '{bundle}'"
                ).format(
                    bundle=bundle.name,
                    item=item_id,
                ))

            for id, key in attributes['keys'].items():
                if 'private_key' not in key.keys():
                    raise BundleError(_(
                        "no private key set for {item} in bundle '{bundle}'"
                    ).format(
                        bundle=bundle.name,
                        item=item_id,
                    ))
                if 'public_key' not in key.keys():
                    raise BundleError(_(
                        "no public key set for {item} in bundle '{bundle}'"
                    ).format(
                        bundle=bundle.name,
                        item=item_id,
                    ))

    #
    # def patch_attributes(self, attributes):
    #     if attributes['soa']['nameserver'][-1] != '.':
    #         attributes['soa']['nameserver'] += '.'
    #
    #     if attributes['soa']['postmaster'][-1] != '.':
    #         attributes['soa']['postmaster'] += '.'
    #
    #     attributes['soa']['postmaster'] = attributes['soa']['postmaster'].replace('@', '.')
    #
    #     if 'default_ttl' not in attributes:
    #         attributes['default_ttl'] = 60
    #
    #     return attributes

    @classmethod
    def get_auto_deps(cls, items):
        deps = []
        for item in items:
            # debian TODO: add other package manager
            if item.ITEM_TYPE_NAME == 'pkg_apt' and item.name in ['powerdns', 'dns-tools']:
                deps.append(item.id)

        return deps
