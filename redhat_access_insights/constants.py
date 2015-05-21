"""
Constants
"""


class InsightsConstants(object):
    app_name = 'redhat-access-insights'
    version = '1.0.3'
    auth_method = 'BASIC'
    log_level = 'DEBUG'
    user_agent = app_name + '/' + version
    default_conf_dir = '/etc/' + app_name + '/'
    log_dir = '/var/log/' + app_name
    default_log_file = log_dir + app_name + '.log'
    default_conf_file = default_conf_dir + app_name + '.conf'
    default_ca_file = default_conf_dir + 'cert-api.access.redhat.com.pem'
    dynamic_conf_url = ('https://cert-api.access.redhat.com/'
                        'r/insights/v1/static/uploader.json')
    upload_url = 'https://cert-api.access.redhat.com/r/insights'
    api_url = 'https://cert-api.access.redhat.com/r/insights/'
    branch_info_url = ('https://cert-api.access.redhat.com/'
                       'r/insights/v1/branch_info')
    dynamic_conf_file = default_conf_dir + '.cache.json'
    dynamic_fallback_file = default_conf_dir + '.fallback.json'
    dynamic_remove_file = default_conf_dir + 'remove.conf'
    unregistered_file = default_conf_dir + '.unregistered'
    pub_gpg_path = default_conf_dir + 'redhattools.pub.gpg'
    machine_id_file = default_conf_dir + 'machine-id'
