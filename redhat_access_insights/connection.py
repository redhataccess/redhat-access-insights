"""
Module handling HTTP Requests and Connection Diagnostics
"""
import requests
import sys
import os
import json

import traceback
import logging
from utilities import (determine_hostname,
                       generate_machine_id,
                       delete_unregistered_file,
                       write_unregistered_file)
from cert_auth import rhsmCertificate
from constants import InsightsConstants as constants

import xml.etree.ElementTree as ET
APP_NAME = constants.app_name

logger = logging.getLogger(APP_NAME)
"""
urllib3's logging is chatty
"""
URLLIB3_LOGGER = logging.getLogger('urllib3.connectionpool')
URLLIB3_LOGGER.setLevel(logging.WARNING)
URLLIB3_LOGGER = logging.getLogger('requests.packages.urllib3.connectionpool')
URLLIB3_LOGGER.setLevel(logging.WARNING)


class InsightsConnection(object):

    """
    Helper class to manage details about the connection
    """

    def __init__(self, config):
        self.user_agent = constants.user_agent
        self.username = config.get(APP_NAME, "username")
        self.password = config.get(APP_NAME, "password")
        self.upload_url = config.get(APP_NAME, "upload_url")
        self.api_url = config.get(APP_NAME, "api_url")
        self.branch_info_url = config.get(APP_NAME, "branch_info_url")
        self.authmethod = config.get(APP_NAME, 'authmethod')
        self.cert_verify = config.get(APP_NAME, "cert_verify")
        if self.cert_verify.lower() == 'false':
            self.cert_verify = False
        elif self.cert_verify.lower() == 'true':
            self.cert_verify = True
        self.get_proxies(config)
        self._validate_hostnames()
        self.session = self._init_session()

    def _init_session(self):
        """
        Set up the session, auth is handled here
        """
        session = requests.Session()
        session.headers = {'User-Agent': self.user_agent,
                           'Accept': 'application/json'}
        if self.authmethod == "BASIC":
            session.auth = (self.username, self.password)
        elif self.authmethod == "CERT":
            cert = rhsmCertificate.certpath()
            key = rhsmCertificate.keypath()
            session.cert = (cert, key)
        session.verify = self.cert_verify
        session.proxies = self.proxies
        if self.proxy_auth:
            # HACKY
            try:
                # Need to make a request that will fail to get proxies set up
                session.request("GET", "https://api.access.redhat.com")
            except requests.ConnectionError:
                pass
            # Major hack, requests/urllib3 does not make access to
            # proxy_headers easy
            session.adapters['https://'].\
              proxy_manager[self.proxies['https']].\
              proxy_headers = {'Proxy-Authorization': self.proxy_auth}
            session.adapters['https://'].\
              proxy_manager[self.proxies['https']].\
              connection_pool_kw['_proxy_headers'] = {'Proxy-Authorization': self.proxy_auth}
            conns = session.adapters['https://'].\
                      proxy_manager[self.proxies['https']].pools._container
            for conn in conns:
                connection = conns[conn]
                connection.proxy_headers = {'Proxy-Authorization': self.proxy_auth}
        return session

    def get_proxies(self, config):
        """
        Determine proxy configuration
        """
        # Get proxy from ENV or Config
        proxies = None
        proxy_auth = None
        env_proxy = os.environ.get('HTTPS_PROXY')
        if env_proxy:
            if '@' in env_proxy:
                scheme = env_proxy.split(':')[0] + '://'
                logger.debug("Proxy Scheme: %s", scheme)
                location = env_proxy.split('@')[1]
                logger.debug("Proxy Location: %s", location)
                username = env_proxy.split('@')[0].split(
                    ':')[1].replace('/', '')
                logger.debug("Proxy User: %s", username)
                password = env_proxy.split('@')[0].split(':')[2]
                proxy_auth = requests.auth._basic_auth_str(username, password)
                env_proxy = scheme + location
            logger.debug("ENV Proxy: %s", env_proxy)
            proxies = {"https": env_proxy}

        conf_proxy = config.get(APP_NAME, 'proxy')

        if ((conf_proxy is not None and
             conf_proxy.lower() != 'None'.lower() and
             conf_proxy != "")):
            if '@' in conf_proxy:
                scheme = conf_proxy.split(':')[0] + '://'
                logger.debug("Proxy Scheme: %s", scheme)
                location = conf_proxy.split('@')[1]
                logger.debug("Proxy Location: %s", location)
                username = conf_proxy.split(
                    '@')[0].split(':')[1].replace('/', '')
                logger.debug("Proxy User: %s", username)
                password = conf_proxy.split('@')[0].split(':')[2]
                proxy_auth = requests.auth._basic_auth_str(username, password)
                conf_proxy = scheme + location
            logger.debug("CONF Proxy: %s", conf_proxy)
            proxies = {"https": conf_proxy}
        self.proxies = proxies
        self.proxy_auth = proxy_auth

    def _validate_hostnames(self):
        """
        Validate that the hostnames we got from config are sane
        """
        from urlparse import urlparse
        import socket
        endpoint_url = urlparse(self.upload_url)
        try:
            # Ensure we have something in the scheme and netloc
            if endpoint_url.scheme == "" or endpoint_url.netloc == "":
                logger.error("Invalid upload_url: " + self.upload_url + "\n"
                             "Be sure to include a protocol "
                             "(e.g. https://) and a "
                             "fully qualified domain name in " +
                             constants.default_conf_file)
                sys.exit()
            endpoint_addr = socket.gethostbyname(
                endpoint_url.netloc.split(':')[0])
            logger.debug("hostname: %s ip: %s", endpoint_url.netloc, endpoint_addr)
        except socket.gaierror:
            logger.error("Could not resolve hostname: %s", endpoint_url.geturl())
        if self.proxies is not None:
            proxy_url = urlparse(self.proxies['https'])
            try:
                # Ensure we have something in the scheme and netloc
                if proxy_url.scheme == "" or proxy_url.netloc == "":
                    logger.error("Proxies: %s", self.proxies)
                    logger.error("Invalid proxy!"
                                 "Please verify the proxy setting"
                                 " in " + constants.default_conf_file)
                    sys.exit()
                proxy_addr = socket.gethostbyname(
                    proxy_url.netloc.split(':')[0])
                logger.debug("Proxy hostname: %s ip: %s", proxy_url.netloc, proxy_addr)
            except socket.gaierror:
                logger.error("Could not resolve proxy %s", proxy_url.geturl())
                traceback.print_exc()

    def _test_urls(self, url, method):
        """
        Actually test the url
        """
        from urlparse import urlparse
        files = {'file': ("test", "test")}
        url = urlparse(url)
        test_url = url.scheme + "://" + url.netloc
        for ext in (url.path + '/', '', '/rs', '/rs/telemetry'):
            try:
                logger.info("Testing: %s", test_url + ext)
                if method is "POST":
                    test_req = self.session.post(
                        test_url + ext, timeout=10, files=files)
                elif method is "GET":
                    test_req = self.session.get(test_url + ext, timeout=10)
                logger.info("HTTP Status Code: %d", test_req.status_code)
                logger.info("HTTP Status Text: %s", test_req.reason)
                logger.debug("HTTP Response Text: %s", test_req.text)
                # Strata returns 405 on a GET sometimes, this isn't a big deal
                if test_req.status_code == 200 or test_req.status_code == 201:
                    logger.info("Successfully connected to: %s", test_url + ext)
                    return
                else:
                    logger.info("Connection failed")
            except requests.ConnectionError, exc:
                last_ex = exc
                logger.error("Could not successfully connect to: %s", test_url + ext)
                print exc
        if last_ex:
            raise last_ex

    def test_connection(self):
        """
        Test connection to Red Hat
        """
        logger.info("Connection test config:")
        logger.info("Proxy config: %s", self.proxies)
        logger.info("Certificate Verification: %s", self.cert_verify)
        try:
            logger.info("\nTesting upload_url connection:")
            self._test_urls(self.upload_url, "POST")
            logger.info("upload_url test success")
            logger.info("\nTesting api_url connection:")
            self._test_urls(self.api_url, "GET")
            logger.info("api_url test success")
            logger.info("\nConnectivity tests completed successfully")
        except requests.ConnectionError, exc:
            print exc
            logger.error('Connectivity test failed! '
                         'Please check your network configuration')
            logger.error('Additional information may be in'
                         ' /var/log/' + APP_NAME + "/" + APP_NAME + ".log")
            sys.exit(1)
        sys.exit()

    def handle_fail_rcs(self, req):
        """
        Bail out if we get a 401 and leave a message
        """
        if req.status_code >= 400:
            logger.error("Upload failed!")
            logger.info("HTTP Status Code: %s", req.status_code)
            logger.info("HTTP Status Text: %s", req.reason)
            logger.debug("HTTP Response Text: %s", req.text)
            if req.status_code == 401:
                logger.error("Authorization Required.")
                logger.error("Please ensure correct credentials "
                             "in " + constants.default_conf_file)
            if req.status_code == 412:
                try:
                    unreg_date = req.json()['unregistered_at']
                except LookupError:
                    unreg_date = "412, but no unreg_date"
                write_unregistered_file(unreg_date)
            sys.exit(1)

    def check_registration(self):
        """
        Check if we were unregistered
        """
        registration_url = self.api_url + '/v1/systems/' + generate_machine_id()
        logger.debug("Checking registration status: %s", registration_url)
        system_info = self.session.get(registration_url)

        if system_info.status_code == 404:
            # This system hasn't been registered and is it's first upload
            return
        elif system_info.status_code == 200:
            system_info = system_info.json()
            logger.debug("System info: %s", json.dumps(system_info))
        else:
            self.handle_fail_rcs(system_info)
            logger.error("Could not check blacklist")
            sys.exit(1)

        try:
            if system_info['unregistered_at']:
                write_unregistered_file(system_info['unregistered_at'])
            else:
                logger.debug("This machine is registered")
        except LookupError:
            logger.debug("This machine is registered")

    def get_satellite5_info(self, branch_info):
        """
        Get remote_leaf for Satellite 5 Managed box
        """
        logger.debug(
            "Remote branch not -1 but remote leaf is -1, must be Satellite 5")
        if os.path.isfile('/etc/sysconfig/rhn/systemid'):
            logger.debug("Found systemid file")
            sat5_conf = ET.parse('/etc/sysconfig/rhn/systemid').getroot()
            leaf_id = None
            for member in sat5_conf.getiterator('member'):
                if member.find('name').text == 'system_id':
                    logger.debug("Found member 'system_id'")
                    leaf_id = member.find('value').find(
                        'string').text.split('ID-')[1]
                    logger.debug("Found leaf id: %s", leaf_id)
                    branch_info['remote_leaf'] = leaf_id
            if leaf_id is None:
                raise Exception("Could not determine leaf_id!  Exiting!")

    def branch_info(self):
        """
        Retrieve branch_info from Satellite Server
        """
        logger.debug("Obtaining branch information from %s", self.branch_info_url)
        branch_info = self.session.get(self.branch_info_url)
        logger.debug("GET branch_info status: %s", branch_info.status_code)
        logger.debug("Branch information: %s", json.dumps(branch_info.json()))
        branch_info = branch_info.json()

        # Determine if we are connected to Satellite 5
        if ((branch_info['remote_branch'] is not -1 and
             branch_info['remote_leaf'] is -1)):
            self.get_satellite5_info(branch_info)

        return branch_info

    def create_system(self, new_machine_id=False):
        """
        Create the machine via the API
        """
        client_hostname = determine_hostname()
        machine_id = generate_machine_id(new_machine_id)

        try:
            branch_info = self.branch_info()
            remote_branch = branch_info['remote_branch']
            remote_leaf = branch_info['remote_leaf']

        except LookupError:
            logger.error("ERROR: Could not determine branch information, exiting!")
            logger.error("See %s for more information", constants.default_log_file)
            logger.error("Could not register system, running configuration test")
            self.test_connection()

        except requests.ConnectionError:
            logger.error("ERROR: Could not determine branch information, exiting!")
            logger.error("See %s for more information", constants.default_log_file)
            logger.error("Could not register system, running configuration test")
            self.test_connection()

        data = {'machine_id': machine_id,
                'remote_branch': remote_branch,
                'remote_leaf': remote_leaf,
                'hostname': client_hostname}
        data = json.dumps(data)
        headers = {'Content-Type': 'application/json'}
        post_system_url = self.api_url + '/v1/systems'
        logger.debug("POST System: %s", post_system_url)
        logger.debug(data)
        system = None
        try:
            system = self.session.post(post_system_url,
                                       headers=headers,
                                       data=data)
            logger.debug("POST System status: %d", system.status_code)
        except requests.ConnectionError:
            logger.error("Could not register system, running configuration test")
            self.test_connection()
        return system

    def do_group(self, group_id):
        """
        Do grouping on register
        """
        api_group_id = None
        headers = {'Content-Type': 'application/json'}
        group_path = self.api_url + '/v1/groups'
        group_get_path = group_path + ('?display_name=%s' % group_id)

        logger.debug("GET group: %s", group_get_path)
        get_group = self.session.get(group_get_path)
        logger.debug("GET group status: %s", get_group.status_code)
        if get_group.status_code == 200:
            api_group_id = get_group.json()['id']

        if get_group.status_code == 404:
            # Group does not exist, POST to create
            logger.debug("POST group")
            data = json.dumps({'display_name': group_id})
            post_group = self.session.post(group_path,
                                           headers=headers,
                                           data=data)
            logger.debug("POST group status: %s", post_group.status_code)
            logger.debug("POST Group: %s", post_group.json())
            self.handle_fail_rcs(post_group)
            api_group_id = post_group.json()['id']

        logger.debug("PUT group")
        data = json.dumps({'machine_id': generate_machine_id()})
        put_group = self.session.put(group_path +
                                     ('/%s/systems' % api_group_id),
                                     headers=headers,
                                     data=data)
        logger.debug("PUT group status: %d", put_group.status_code)
        logger.debug("PUT Group: %s", put_group.json())

    def register(self, group_id=None):
        """
        Register this machine
        """

        delete_unregistered_file()

        client_hostname = determine_hostname()
        # This will undo a blacklist
        logger.debug("API: Create system")
        system = self.create_system(new_machine_id=False)

        # If we get a 409, we know we need to generate a new machine-id
        if system.status_code == 409:
            system = self.create_system(new_machine_id=True)
        self.handle_fail_rcs(system)

        logger.debug("System: %s", system.json())

        # Do grouping
        if group_id is not None:
            self.do_group(group_id)

        if group_id is not None:
            return (client_hostname, group_id)
        else:
            return (client_hostname, "None")

    def upload_archive(self, data_collected):
        """
        Do an HTTPS Upload of the archive
        """
        file_name = os.path.basename(data_collected)
        files = {'file': (file_name, open(data_collected, 'rb'))}

        upload_url = self.upload_url + '/' + generate_machine_id()
        logger.debug("Uploading %s to %s", data_collected, upload_url)
        upload = self.session.post(upload_url, files=files)

        self.handle_fail_rcs(upload)
        logger.debug("Upload status: %s %s %s",
                     upload.status_code, upload.reason, upload.text)
        logger.debug("Upload duration: %s", upload.elapsed)
        logger.info("Upload completed successfully!")
        return upload.status_code
