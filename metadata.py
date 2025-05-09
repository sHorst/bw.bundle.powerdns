defaults = {}

if node.has_bundle("apt"):
    defaults['apt'] = {
        'packages': {
            'pdns-server': {'installed': True, },
            # Install sqlite3 backend, to access dnssec db
            'pdns-backend-sqlite3': {
                'installed': True,
                'needed_by': [
                    'action:create_dnssec_db',
                ]
            },
            'dnsutils': {'installed': True, },
        }
    }
    if node.os == 'debian' and node.os_version[0] > 8:
        defaults['apt']['packages']['pdns-tools'] = {'installed': True, }


@metadata_reactor
def add_iptables_rule(metadata):
    if not node.has_bundle("iptables"):
        raise DoNotRunAgain

    interfaces = ['main_interface']
    interfaces += metadata.get('powerdns/additional_interfaces', [])

    meta_tables = {}
    for interface in interfaces:
        meta_tables += repo.libs.iptables.accept().chain('INPUT').input(interface).tcp().dest_port(53)
        meta_tables += repo.libs.iptables.accept().chain('INPUT').input(interface).udp().dest_port(53)

    return meta_tables


@metadata_reactor
def add_recursor_to_apt(metadata):
    if metadata.get('powerdns/recursor/enabled', False):
        return {
            'apt': {
                'packages': {
                    'pdns-recursor': {'installed': True, },
                },
            },
        }

    return {}
