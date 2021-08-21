defaults = {}

if node.has_bundle("apt"):
    defaults['apt'] = {
        'packages': {
            'pdns-server': {'installed': True, },
            'dnsutils': {'installed': True, },
        }
    }
    if node.os == 'debian' and node.os_version[0] > 8:
        defaults['apt']['packages']['pdns-tools'] = {'installed': True, },

if node.has_bundle('iptables'):
    defaults += repo.libs.iptables.accept().chain('INPUT').tcp().dest_port(53)
    defaults += repo.libs.iptables.accept().chain('INPUT').udp().dest_port(53)


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
