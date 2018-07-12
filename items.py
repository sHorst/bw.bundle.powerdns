from bundlewrap.exceptions import BundleError


def add_dot(url):
    if url[-1] != '.':
        url += '.'

    return url


def add_to_list_or_create(ilist, key, value):
    if key not in ilist:
        ilist[key] = []

    ilist[key] += [value, ]


pkg_apt = {
    'pdns-server': {
        'installed': True
    },
    'pdns-tools': {
        'installed': True
    },
    'dnsutils': {
        'installed': True
    },
}

svc_systemd = {
    "pdns": {
        'needs': [
            'pkg_apt:pdns-server',
        ],
    }
}

default_config = {
    # 8bit-dns	Allow 8bit dns queries
    '8bit-dns': 'no',

    # allow-axfr-ips	Allow zonetransfers only to these subnets
    'allow-axfr-ips': '127.0.0.0/8,::1',

    # allow-dnsupdate-from	A global setting to allow DNS updates from these IP ranges.
    'allow-dnsupdate-from': '127.0.0.0/8,::1',

    # allow-notify-from	Allow AXFR NOTIFY from these IP ranges. If empty, drop all incoming notifies.
    'allow-notify-from': '0.0.0.0/0,::/0',

    # allow-recursion	List of subnets that are allowed to recurse
    'allow-recursion': '0.0.0.0/0',

    # allow-unsigned-notify	Allow unsigned notifications for TSIG secured domains
    'allow-unsigned-notify': 'yes',

    # allow-unsigned-supermaster	Allow supermasters to create zones without TSIG signed NOTIFY
    'allow-unsigned-supermaster': 'yes',

    # also-notify	When notifying a domain, also notify these nameservers
    'also-notify': '',

    # any-to-tcp	Answer ANY queries with tc=1, shunting to TCP
    'any-to-tcp': 'yes',

    # api	Enable/disable the REST API
    'api': 'no',

    # api-key	Static pre-shared authentication key for access to the REST API
    'api-key': '',

    # api-logfile	Location of the server logfile (used by the REST API)
    'api-logfile': '/var/log/pdns.log',

    # api-readonly	Disallow data modification through the REST API when set
    'api-readonly': 'no',

    # cache-ttl	Seconds to store packets in the PacketCache
    'cache-ttl': '20',

    # carbon-interval	Number of seconds between carbon (graphite) updates
    'carbon-interval': '30',

    # carbon-ourname	If set, overrides our reported hostname for carbon stats
    'carbon-ourname': '',

    # carbon-server	If set, send metrics in carbon (graphite) format to this server
    'carbon-server': '',

    # chroot	If set, chroot to this directory for more security
    'chroot': '',

    # config-dir	Location of configuration directory (pdns.conf)
    'config-dir': '/etc/powerdns',

    # config-name	Name of this virtual configuration - will rename the binary image
    'config-name': '',

    # control-console	Debugging switch - don't use
    'control-console': 'no',

    # daemon	Operate as a daemon
    'daemon': 'no',

    # default-ksk-algorithms	Default KSK algorithms
    'default-ksk-algorithms': 'ecdsa256',

    # default-ksk-size	Default KSK size (0 means default)
    'default-ksk-size': '0',

    # default-soa-edit	Default SOA-EDIT value
    'default-soa-edit': '',

    # default-soa-edit-signed	Default SOA-EDIT value for signed zones
    'default-soa-edit-signed': '',

    # default-soa-mail	mail address to insert in the SOA record if none set in the backend
    'default-soa-mail': '',

    # default-soa-name	name to insert in the SOA record if none set in the backend
    'default-soa-name': 'a.misconfigured.powerdns.server',

    # default-ttl	Seconds a result is valid if not set otherwise
    'default-ttl': '3600',

    # default-zsk-algorithms	Default ZSK algorithms
    'default-zsk-algorithms': '',

    # default-zsk-size	Default ZSK size (0 means default)
    'default-zsk-size': '0',

    # direct-dnskey	Fetch DNSKEY RRs from backend during DNSKEY synthesis
    'direct-dnskey': 'no',

    # disable-axfr	Disable zonetransfers but do allow TCP queries
    'disable-axfr': 'no',

    # disable-axfr-rectify	Disable the rectify step during an outgoing AXFR. Only required for regression testing.
    'disable-axfr-rectify': 'no',

    # disable-syslog	Disable logging to syslog, useful when running inside a supervisor that logs stdout
    'disable-syslog': 'no',

    # disable-tcp	Do not listen to TCP queries
    'disable-tcp': 'no',

    # distributor-threads	Default number of Distributor (backend) threads to start
    'distributor-threads': '3',

    # dname-processing	If we should support DNAME records
    'dname-processing': 'no',

    # dnssec-key-cache-ttl	Seconds to cache DNSSEC keys from the database
    'dnssec-key-cache-ttl': '30',

    # dnsupdate	Enable/Disable DNS update (RFC2136) support. Default is no.
    'dnsupdate': 'no',

    # do-ipv6-additional-processing	Do AAAA additional processing
    'do-ipv6-additional-processing': 'yes',

    # domain-metadata-cache-ttl	Seconds to cache domain metadata from the database
    'domain-metadata-cache-ttl': '60',

    # edns-subnet-processing	If we should act on EDNS Subnet options
    'edns-subnet-processing': 'no',

    # entropy-source	If set, read entropy from this file
    'entropy-source': '/dev/urandom',

    # experimental-lua-policy-script	Lua script for the policy engine
    'experimental-lua-policy-script': '',

    # forward-dnsupdate	A global setting to allow DNS update packages that are for a Slave domain, to be forwarded to the master.
    'forward-dnsupdate': 'yes',

    # guardian	Run within a guardian process
    'guardian': 'no',

    # include-dir	Include *.conf files from this directory
    'include-dir': '',

    # launch	Which backends to launch and order to query them in
    'launch': None,

    # load-modules	Load this module - supply absolute or relative path
    'load-modules': '',

    # local-address	Local IP addresses to which we bind
    'local-address': '0.0.0.0',

    # local-address-nonexist-fail	Fail to start if one or more of the local-address's do not exist on this server
    'local-address-nonexist-fail': 'yes',

    # local-ipv6	Local IP address to which we bind
    'local-ipv6': '::',

    # local-ipv6-nonexist-fail	Fail to start if one or more of the local-ipv6 addresses do not exist on this server
    'local-ipv6-nonexist-fail': 'yes',

    # local-port	The port on which we listen
    'local-port': '53',

    # log-dns-details	If PDNS should log DNS non-erroneous details
    'log-dns-details': 'no',

    # log-dns-queries	If PDNS should log all incoming DNS queries
    'log-dns-queries': 'no',

    # logging-facility	Log under a specific facility
    'logging-facility': '',

    # loglevel	Amount of logging. Higher is more. Do not set below 3
    'loglevel': '4',

    # lua-prequery-script	Lua script with prequery handler (DO NOT USE)
    'lua-prequery-script': '',

    # master	Act as a master
    'master': 'no',

    # max-cache-entries	Maximum number of cache entries
    'max-cache-entries': '1000000',

    # max-ent-entries	Maximum number of empty non-terminals in a zone
    'max-ent-entries': '100000',

    # max-nsec3-iterations	Limit the number of NSEC3 hash iterations
    'max-nsec3-iterations': '500',

    # max-queue-length	Maximum queuelength before considering situation lost
    'max-queue-length': '5000',

    # max-signature-cache-entries	Maximum number of signatures cache entries
    'max-signature-cache-entries': '',

    # max-tcp-connections	Maximum number of TCP connections
    'max-tcp-connections': '20',

    # module-dir	Default directory for modules
    'module-dir': '',


    # negquery-cache-ttl	Seconds to store negative query results in the QueryCache
    'negquery-cache-ttl': '60',

    # no-shuffle	Set this to prevent random shuffling of answers - for regression testing
    'no-shuffle': 'off',

    # non-local-bind	Enable binding to non-local addresses by using FREEBIND / BINDANY socket options
    'non-local-bind': 'no',

    # only-notify	Only send AXFR NOTIFY to these IP addresses or netmasks
    'only-notify': '0.0.0.0/0,::/0',

    # out-of-zone-additional-processing	Do out of zone additional processing
    'out-of-zone-additional-processing': 'yes',

    # outgoing-axfr-expand-alias	Expand ALIAS records during outgoing AXFR
    'outgoing-axfr-expand-alias': 'no',

    # overload-queue-length	Maximum queuelength moving to packetcache only
    'overload-queue-length': '0',

    # prevent-self-notification	Don't send notifications to what we think is ourself
    'prevent-self-notification': 'yes',

    # query-cache-ttl	Seconds to store query results in the QueryCache
    'query-cache-ttl': '20',

    # query-local-address	Source IP address for sending queries
    'query-local-address': '0.0.0.0',

    # query-local-address6	Source IPv6 address for sending queries
    'query-local-address6': '::',

    # query-logging	Hint backends that queries should be logged
    'query-logging': 'no',

    # queue-limit	Maximum number of milliseconds to queue a query
    'queue-limit': '1500',

    # receiver-threads	Default number of receiver threads to start
    'receiver-threads': '1',

    # recursive-cache-ttl	Seconds to store packets for recursive queries in the PacketCache
    'recursive-cache-ttl': '10',

    # recursor	If recursion is desired, IP address of a recursing nameserver
    'recursor': 'no',

    # retrieval-threads	Number of AXFR-retrieval threads for slave operation
    'retrieval-threads': '2',

    # reuseport	Enable higher performance on compliant kernels by using SO_REUSEPORT allowing each receiver thread to open its own socket
    'reuseport': 'no',

    # security-poll-suffix	Domain name from which to query security update notifications
    'security-poll-suffix': 'secpoll.powerdns.com.',

    # server-id	Returned when queried for 'server.id' TXT or NSID, defaults to hostname - disabled or custom
    'server-id': '',

    # setgid	If set, change group id to this gid for more security
    'setgid': '',

    # setuid	If set, change user id to this uid for more security
    'setuid': '',

    # signing-threads	Default number of signer threads to start
    'signing-threads': '3',

    # slave	Act as a slave
    'slave': 'no',

    # slave-cycle-interval	Schedule slave freshness checks once every .. seconds
    'slave-cycle-interval': '60',

    # slave-renotify	If we should send out notifications for slaved updates
    'slave-renotify': 'no',

    # soa-expire-default	Default SOA expire
    'soa-expire-default': '604800',

    # soa-minimum-ttl	Default SOA minimum ttl
    'soa-minimum-ttl': '3600',

    # soa-refresh-default	Default SOA refresh
    'soa-refresh-default': '10800',

    # soa-retry-default	Default SOA retry
    'soa-retry-default': '3600',

    # socket-dir	Where the controlsocket will live, /var/run when unset and not chrooted
    'socket-dir': '',

    # tcp-control-address	If set, PowerDNS can be controlled over TCP on this address
    'tcp-control-address': '',

    # tcp-control-port	If set, PowerDNS can be controlled over TCP on this address
    'tcp-control-port': '53000',

    # tcp-control-range	If set, remote control of PowerDNS is possible over these networks only
    'tcp-control-range': '127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12, ::1/128, fe80::/10',

    # tcp-control-secret	If set, PowerDNS can be controlled over TCP after passing this secret
    'tcp-control-secret': '',

    # traceback-handler	Enable the traceback handler (Linux only)
    'traceback-handler': 'yes',

    # trusted-notification-proxy	IP address of incoming notification proxy
    'trusted-notification-proxy': '',

    # udp-truncation-threshold	Maximum UDP response size before we truncate
    'udp-truncation-threshold': '1680',

    # version-string	PowerDNS version in packets - full, anonymous, powerdns or custom
    'version-string': 'full',

    # webserver	Start a webserver for monitoring
    'webserver': 'no',

    # webserver-address	IP Address of webserver to listen on
    'webserver-address': '127.0.0.1',

    # webserver-allow-from	Webserver access is only allowed from these subnets
    'webserver-allow-from': '0.0.0.0/0,::/0',

    # webserver-password	Password required for accessing the webserver
    'webserver-password': '',

    # webserver-port	Port of webserver to listen on
    'webserver-port': '8081',

    # webserver-print-arguments	If the webserver should print arguments
    'webserver-print-arguments': 'no',

    # write-pid	Write a PID file
    'write-pid': 'yes',

    # xfr-max-received-mbytes	Maximum number of megabytes received from an incoming XFR
    'xfr-max-received-mbytes': '100',
}

pdns_configs = {
    'include-dir': '/etc/powerdns/pdns.d',
    'launch': '',
    'security-poll-suffix': '',
    'setgid': 'pdns',
    'setuid': 'pdns',
}

pdns_configs.update(node.metadata.get('powerdns', {}).get('config', {}))

content = []
for key, value in pdns_configs.items():
    if default_config.get(key, None) != value:
        content.append('{}={}'.format(key, value))


files = {
    '/etc/powerdns/pdns.conf': {
        'content': '\n'.join(content) + '\n',
        'mode': "0600",
        'owner': 'root',
        'group': 'root',
        'triggers': [
            "svc_systemd:pdns:restart"
        ],
    }
}

dnssec_db = node.metadata\
    .get('powerdns', {}).get('backends', {})\
    .get('bind', {})\
    .get('config', {})\
    .get('bind-dnssec-db', '/var/lib/powerdns/bind-dnssec-db.sqlite3')


actions = {
    "create_dnssec_db": {
        'command': "pdnsutil create-bind-db {dnssec_db}".format(dnssec_db=dnssec_db),
        'unless': "test -f {dnssec_db}".format(dnssec_db=dnssec_db),
        'cascade_skip': False,
        'needs': ["pkg_apt:pdns-server"],
        'triggers': ['svc_systemd:pdns:restart'],
    },
}

directories = {}
zonefiles = {}

for backend, config in node.metadata.get('powerdns', {}).get('backends', {}).items():
    apt = config.get('apt', 'pdns-backend-{}'.format(backend))
    pkg_apt[apt] = {
       'installed': True,
       'needs': ['pkg_apt:pdns-server'],
       'needed_by': ['svc_systemd:pdns']
    }

    backend_config = {}
    backend_default_config = {}
    backend_config_filename = 'pdns.local.{}.conf'.format(backend)

    if backend == 'gmysql':
        backend_default_config = {
            'gmysql-host': 'localhost',
            'gmysql-port': '3306',
            'gmysql-dbname': '',
            'gmysql-user': '',
            'gmysql-password': '',
            'gmysql-dnssec': 'no',
        }
        backend_config = {
            'launch+': 'gmysql',
        }
    elif backend == 'bind':
        backend_config_filename = 'bind.conf'
        backend_default_config = {
            # bind-check-interval	Interval for zonefile changes
            'bind-check-interval': '0',

            # bind-config	Location of named.conf
            'bind-config': '',

            # bind-dnssec-db	Filename to store & access our DNSSEC metadatabase, empty for none
            'bind-dnssec-db': '',

            # bind-hybrid	Store DNSSEC metadata in other backend
            'bind-hybrid': 'no',

            # bind-ignore-broken-records	Ignore records that are out-of-bound for the zone.
            'bind-ignore-broken-records': 'no',

            # bind-supermaster-config	Location of (part of) named.conf where pdns can write zone-statements to
            'bind-supermaster-config': '',

            # bind-supermaster-destdir	Destination directory for newly added slave zones
            'bind-supermaster-destdir': '',

            # bind-supermasters	List of IP-addresses of supermasters
            'bind-supermasters': '',
        }
        backend_config = {
            'launch+': 'bind',
            'bind-supermaster-config': '/var/lib/powerdns/supermaster.conf',
            'bind-supermaster-destdir': '/var/lib/powerdns/zones.slave.d',
        }

        zonefile_directory = config.get('zonefile_directory', '/var/lib/powerdns/zones')

        directories[zonefile_directory] = {
            'owner': 'root',
            'group': 'pdns',
            'mode': "0750",
            'needs': ['pkg_apt:{}'.format(apt)],
        }

        named_config = [
            '# Debian default: supermaster created zones are written here:',
            'include "/var/lib/powerdns/supermaster.conf";',
        ]

        # load zonefiles
        for zone, zone_config in config.get('zones', {}).items():
            named_config.append('zone "{}" IN {{'.format(zone))
            named_config.append('    type {};'.format(zone_config.get('type', 'master')))
            named_config.append('    file "{}/{}.zone";'.format(zonefile_directory, zone))
            named_config.append('};')

            # create ns records we add a . to the end of every domain, since we assume they are absolute
            ns_records = []
            for ns in zone_config.get('name_servers', []):
                ns_records += [{'ttl': 86400, 'type': 'NS', 'value': add_dot(ns)}, ]

            actions['notify_zone_{}'.format(zone)] = {
                'command': "pdns_control notify {zone}".format(zone=zone),
                'triggered': True,
            }

            zonefiles[zone] = {
                'soa': {
                    'nameserver': zone_config.get('name_servers', [''])[0],
                    'postmaster': zone_config.get('soa', {}).get('hostmaster', 'hostmaster@ultrachaos.de'),
                    'refresh': zone_config.get('soa', {}).get('refresh', 14400),
                    'retry': zone_config.get('soa', {}).get('retry', 7200),
                    'expire': zone_config.get('soa', {}).get('expire', 604800),
                    'minimum': zone_config.get('soa', {}).get('minimum', 14400),
                },
                'records': {
                    '': ns_records,
                },
                'default_ttl': zone_config.get('default_ttl', 300),
                'zonefile_directory': zonefile_directory,
                'triggers': ['svc_systemd:pdns:restart', 'action:notify_zone_{}'.format(zone)],
                'needs': ['pkg_apt:pdns-server', 'directory:{}'.format(zonefile_directory)],
            }

            zone_type = zone_config.get('zone_type', "static")

            if zone_type == 'dyndns':
                zonefiles[zone]['dynamic'] = True
            elif zone_type == 'group':
                if 'group' not in zone_config:
                    raise BundleError("zonetype is group, but no group defined")

                for gnode in sorted(repo.nodes_in_group(zone_config['group'])):
                    for interface, interface_config in zone_config.get('interfaces', {}).items():
                        ip = gnode.metadata.get('interfaces', {})\
                            .get(interface, {})\
                            .get('ip_addresses', [None, ])[0]

                        gnode_name = gnode.name.split('.')[-1]

                        if ip:
                            add_to_list_or_create(
                                zonefiles[zone]['records'],
                                '{net}.{name}'.format(net=interface, name=gnode_name),
                                {'type': 'A', 'value': ip}
                            )

                            if interface_config.get('cname', False):
                                add_to_list_or_create(
                                    zonefiles[zone]['records'],
                                    '{}'.format(gnode_name),
                                    {
                                        'type': 'CNAME', 'value': '{net}.{name}'.format(
                                            net=interface,
                                            name=gnode_name
                                        )
                                    }
                                )

                    for name, record in sorted(gnode.metadata.get('powerdns', {}).get('extra_srv_records', {}).items()):
                        add_to_list_or_create(
                            zonefiles[zone]['records'],
                            name,
                            {'type': 'SRV', 'value': (
                                record.get('priority', 10),
                                record.get('weight', 10),
                                record.get('port'),
                                record.get('server')
                            )}
                        )

            extra_records = zone_config.get('records', {})
            for name, items in sorted(extra_records.items()):
                for item in items:
                    add_to_list_or_create(
                        zonefiles[zone]['records'],
                        name,
                        {'type': item.get('type', 'A'), 'value': item.get('value', '')},
                    )

        files['/etc/powerdns/named.conf'] = {
            'content': '\n'.join(named_config) + '\n',
            'mode': "0640",
            'owner': 'root',
            'group': 'pdns',
            'triggers': [
                "svc_systemd:pdns:restart"
            ],
        }

    backend_config.update(config.get('config', {}))

    content = []
    for key, value in backend_config.items():
        if backend_default_config.get(key, None) != value:
            content.append('{}={}'.format(key, value))

    if config.get('enabled', False):
        files['/etc/powerdns/pdns.d/{}'.format(backend_config_filename)] = {
            'content': '\n'.join(content) + '\n',
            'mode': "0640",
            'owner': 'root',
            'group': 'root',
            'triggers': [
                "svc_systemd:pdns:restart"
            ],
        }
    else:
        files['/etc/powerdns/pdns.d/{}'.format(backend_config_filename)] = {
            'deleted': True,
            'triggers': [
                "svc_systemd:pdns:restart"
            ],
        }

