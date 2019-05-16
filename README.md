PowerDNS Modul
--------------

This module installs PowerDNS.

Dependencies
------------
- [apt-Bundle](https://github.com/sHorst/bw.bundle.apt)

Install
-------

To make this bundle work, you need to insert the items/zone_file.py.py to the bw repository. This can be done with this command:

```
ln -s ../bundles/powerdns/items/zone_file.py items/zone_file.py
```

Demo Metadata
-------------

```
'powerdns': {
    'config': {
        'launch': 'bind',
        'bind-config': '/etc/powerdns/named.conf',
        'recursor': '85.214.20.141',
    },
    'backends': {
        'bind': {
            'zones': {
                'example.lan': {
                    'name_servers': ['ns.example.org'],
                    'soa': {
                        'hostmaster': 'example@example.org',
                    },
                    'zone_type': 'group',
                    'group': 'dns.lan',
                    'interfaces': {
                        'eth0': {
                            'cname': True,
                        },
                    },
                    'records': {
                        'fooclient': [
                            {
                                'type': 'A',
                                'value': '10.15.4.92',
                            },
                        ],
                    },
                },
            },
        },
    },
},
```
