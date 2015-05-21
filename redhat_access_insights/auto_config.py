"""
Auto Configuration Helper
"""
import logging
import os
import requests
from constants import InsightsConstants as constants
from cert_auth import rhsmCertificate
from connection import InsightsConnection

logger = logging.getLogger(constants.app_name)
APP_NAME = constants.app_name


def verify_connectivity(config):
    """
    Verify connectivity to satellite server
    """
    logger.debug("Verifying Connectivity")
    ic = InsightsConnection(config)
    try:
        branch_info = ic.branch_info()
    except requests.ConnectionError:
        logger.debug("Failed to connect to satellite")
        return False
    except LookupError:
        logger.debug("Failed to parse response from satellite")
        return False

    try:
        remote_leaf = branch_info['remote_leaf']
        return remote_leaf
    except LookupError:
        logger.debug("Failed to find accurate branch_info")
        return False


def set_auto_configuration(config, hostname, ca_cert, proxy):
    """
    Set config based on discovered data
    """
    logger.debug("Attempting to auto conf %s %s %s %s", config, hostname, ca_cert, proxy)
    saved_upload_url = config.get(APP_NAME, 'upload_url')
    saved_api_url = config.get(APP_NAME, 'api_url')
    saved_branch_info_url = config.get(APP_NAME, 'branch_info_url')
    saved_dynamic_config_url = config.get(APP_NAME, 'dynamic_config_url')
    if ca_cert is not None:
        config.set(APP_NAME, 'cert_verify', ca_cert)
        saved_cert_verify = config.get(APP_NAME, 'cert_verify')
    if proxy is not None:
        saved_proxy = config.get(APP_NAME, 'proxy')
        config.set(APP_NAME, 'proxy', proxy)
    config.set(APP_NAME, 'upload_url', 'https://' + hostname + '/rs/telemetry')
    config.set(APP_NAME, 'api_url', 'https://' + hostname + '/rs/telemetry/api')
    config.set(APP_NAME, 'branch_info_url', 'https://' +
               hostname + '/rs/telemetry/api/v1/branch_info')
    config.set(APP_NAME, 'dynamic_config_url', 'https://' +
               hostname + '/rs/telemetry/api/v1/static/uploader.json')

    if not verify_connectivity(config):
        logger.warn("Could not auto configure, falling back to static config")
        logger.warn("See %s for additional information", constants.default_log_file)
        config.set(APP_NAME, 'upload_url', saved_upload_url)
        config.set(APP_NAME, 'api_url', saved_api_url)
        config.set(APP_NAME, 'branch_info_url', saved_branch_info_url)
        config.set(APP_NAME, 'dynamic_config_url', saved_dynamic_config_url)
        if proxy is not None:
            if saved_proxy is not None and saved_proxy.lowercase == 'none':
                saved_proxy = None
            config.set(APP_NAME, 'proxy', saved_proxy)
        if ca_cert is not None:
            config.set(APP_NAME, 'cert_verify', saved_cert_verify)


def _try_satellite6_configuration(config):
    """
    Try to autoconfigure for Satellite 6
    """
    try:
        from rhsm.config import initConfig
        rhsm_config = initConfig()

        logger.debug('Trying to autoconf Satellite 6')
        cert = file(rhsmCertificate.certpath(), 'r').read()
        key = file(rhsmCertificate.keypath(), 'r').read()
        rhsm = rhsmCertificate(key, cert)

        # This will throw an exception if we are not registered
        logger.debug('Checking if system is subscription-manager registered')
        rhsm.getConsumerId()
        logger.debug('System is subscription-manager registered')

        rhsm_hostname = rhsm_config.get('server', 'hostname')
        rhsm_proxy_hostname = rhsm_config.get('server', 'proxy_hostname').strip()
        rhsm_proxy_port = rhsm_config.get('server', 'proxy_port').strip()
        rhsm_proxy_user = rhsm_config.get('server', 'proxy_user').strip()
        rhsm_proxy_pass = rhsm_config.get('server', 'proxy_password').strip()
        proxy = None
        if rhsm_proxy_hostname != "":
            logger.debug("Found rhsm_proxy_hostname %s", rhsm_proxy_hostname)
            proxy = "http://"
            if rhsm_proxy_user != "" and rhsm_proxy_pass != "":
                logger.debug("Found user and password for rhsm_proxy")
                proxy = proxy + rhsm_proxy_user + ":" + rhsm_proxy_pass + "@"
                proxy = proxy + rhsm_proxy_hostname + rhsm_proxy_port
            else:
                proxy = proxy + rhsm_proxy_hostname + ':' + rhsm_proxy_port
                logger.debug("RHSM Proxy: %s", proxy)
        logger.debug("Found Satellite Server: %s", rhsm_hostname)
        rhsm_ca = rhsm_config.get('rhsm', 'repo_ca_cert')
        logger.debug("Found CA: %s", rhsm_ca)
        logger.debug("Setting authmethod to CERT")
        config.set(APP_NAME, 'authmethod', 'CERT')

        # Directly connected to Red Hat, use cert auth directly with the api
        if rhsm_hostname == 'subscription.rhn.redhat.com':
            logger.debug("Connected to RH Directly, using cert-api")
            rhsm_hostname = 'cert-api.access.redhat.com'
            rhsm_ca = None
        else:
            # Set the cert verify CA, and path
            rhsm_hostname = rhsm_hostname + '/redhat_access'

        logger.debug("Trying to set auto_configuration")
        set_auto_configuration(config, rhsm_hostname, rhsm_ca, proxy)
        return True
    except:
        logger.debug('System is NOT subscription-manager registered')
        return False


def _try_satellite5_configuration(config):
    """
    Attempt to determine Satellite 5 Configuration
    """
    logger.debug("Trying Satellite 5 auto_config")
    rhn_ca = '/usr/share/rhn/RHN-ORG-TRUSTED-SSL-CERT'
    rhn_config = '/etc/sysconfig/rhn/up2date'
    if os.path.isfile(rhn_ca) and os.path.isfile(rhn_config):
        logger.debug("Found Satellite 5 Certificate and Config")
        rhn_conf_file = file(rhn_config, 'r')
        hostname = None
        for line in rhn_conf_file:
            if line.startswith('serverURL='):
                from urlparse import urlparse
                url = urlparse(line.split('=')[1])
                hostname = url.netloc + '/redhat_access'
                logger.debug("Found hostname %s", hostname)

            # Auto discover proxy stuff
            if line.startswith('enableProxy='):
                proxy_enabled = line.strip().split('=')[1]
            if line.startswith('httpProxy='):
                proxy_host_port = line.strip().split('=')[1]
            if line.startswith('proxyUser='):
                proxy_user = line.strip().split('=')[1]
            if line.startswith('proxyPassword='):
                proxy_password = line.strip().split('=')[1]

        if hostname:
            proxy = None
            if proxy_enabled == "1":
                proxy = "http://"
                if proxy_user != "" and proxy_password != "":
                    logger.debug("Found user and password for rhn_proxy")
                    proxy = proxy + proxy_user + ':' + proxy_password
                    proxy = proxy + "@" + proxy_host_port
                else:
                    proxy = proxy + "@" + proxy_host_port
                    logger.debug("RHN Proxy: %s", proxy)
            set_auto_configuration(config, hostname, rhn_ca, proxy)
        else:
            logger.debug("Could not find hostname")
            return False
        return True
    else:
        logger.debug("Could not find rhn config")
        return False


def try_auto_configuration(config):
    """
    Try to auto-configure if we are attached to a sat5/6
    """
    if not _try_satellite6_configuration(config):
        _try_satellite5_configuration(config)
