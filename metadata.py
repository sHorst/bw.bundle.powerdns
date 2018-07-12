@metadata_processor
def add_iptables_rules(metadata):
    if node.has_bundle('iptables'):
        metadata += repo.libs.iptables.accept().chain('INPUT').tcp().dest_port(53)
        metadata += repo.libs.iptables.accept().chain('INPUT').udp().dest_port(53)

    return metadata, DONE


# @metadata_processor
# def add_restic_rules(metadata):
#     if node.has_bundle('restic'):
#         backup_folders = [
#         ]
#
#         if 'restic' not in metadata:
#             metadata['restic'] = {}
#
#         metadata['restic']['backup_folders'] = metadata['restic'].get('backup_folders', []) + backup_folders
#
#     return metadata, DONE
