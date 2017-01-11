"""
Rules for data collection
"""
import json
import logging
import sys
import six
import shlex
import os
from subprocess import Popen, PIPE, STDOUT
from tempfile import NamedTemporaryFile
from constants import InsightsConstants as constants
from client_config import InsightsClient

APP_NAME = constants.app_name
logger = logging.getLogger(__name__)


class InsightsConfig(object):
    """
    Insights configuration
    """

    def __init__(self, conn):
        """
        Load config from parent
        """
        self.fallback_file = constants.collection_fallback_file
        self.remove_file = constants.collection_remove_file
        self.collection_rules_file = constants.collection_rules_file
        protocol = "https://"
        insecure_connection = InsightsClient.config.getboolean(APP_NAME, "insecure_connection")
        if insecure_connection:
            # This really should not be used.
            protocol = "http://"
        self.base_url = protocol + InsightsClient.config.get(APP_NAME, 'base_url')
        self.collection_rules_url = InsightsClient.config.get(APP_NAME, 'collection_rules_url')
        if self.collection_rules_url is None:
            self.collection_rules_url = self.base_url + '/v1/static/uploader.json'
        self.gpg = InsightsClient.config.getboolean(APP_NAME, 'gpg')
        self.conn = conn

    def validate_gpg_sig(self, path, sig=None):
        """
        Validate the collection rules
        """
        logger.debug("Verifying GPG signature of Insights configuration")
        if sig is None:
            sig = path + ".asc"
        command = ("/usr/bin/gpg --no-default-keyring "
                   "--keyring " + constants.pub_gpg_path +
                   " --verify " + sig + " " + path)
        if not six.PY3:
            command = command.encode('utf-8', 'ignore')
        args = shlex.split(command)
        logger.debug("Executing: %s", args)
        proc = Popen(
            args, shell=False, stdout=PIPE, stderr=STDOUT, close_fds=True)
        stdout, stderr = proc.communicate()
        logger.debug("STDOUT: %s", stdout)
        logger.debug("STDERR: %s", stderr)
        logger.debug("Status: %s", proc.returncode)
        if proc.returncode:
            sys.exit("ERROR: Unable to validate GPG signature! Exiting!")
        else:
            logger.debug("GPG signature verified")
            return True

    def try_disk(self, path, gpg=True):
        """
        Try to load json off disk
        """
        if not os.path.isfile(path):
            return

        if not gpg or self.validate_gpg_sig(path):
            stream = open(path, 'r')
            json_stream = stream.read()
            if len(json_stream):
                try:
                    json_config = json.loads(json_stream)
                    return json_config
                except ValueError:
                    logger.error("ERROR: Invalid JSON in %s", path)
                    sys.exit(1)
            else:
                logger.warn("WARNING: %s was an empty file", path)
                return

    def get_collection_rules(self, raw=False):
        """
        Download the collection rules
        """
        logger.debug("Attemping to download collection rules from %s",
                     self.collection_rules_url)

        req = self.conn.session.get(
            self.collection_rules_url, headers=({'accept': 'text/plain'}))

        if req.status_code == 200:
            logger.debug("Successfully downloaded collection rules")

            json_response = NamedTemporaryFile()
            json_response.write(req.text)
            json_response.file.flush()
        else:
            logger.error("ERROR: Could not download dynamic configuration")
            logger.error("Debug Info: \nConf status: %s", req.status_code)
            logger.error("Debug Info: \nConf message: %s", req.text)
            sys.exit(1)

        if self.gpg:
            self.get_collection_rules_gpg(json_response)

        self.write_collection_data(self.collection_rules_file, req.text)

        if raw:
            return req.text
        else:
            return json.loads(req.text)

    def fetch_gpg(self):
        logger.debug("Attemping to download collection "
                     "rules GPG signature from %s",
                     self.collection_rules_url + ".asc")

        headers = ({'accept': 'text/plain'})
        config_sig = self.conn.session.get(self.collection_rules_url + '.asc',
                                           headers=headers)
        if config_sig.status_code == 200:
            logger.debug("Successfully downloaded GPG signature")
            return config_sig.text
        else:
            logger.error("ERROR: Download of GPG Signature failed!")
            logger.error("Sig status: %s", config_sig.status_code)
            sys.exit(1)

    def get_collection_rules_gpg(self, collection_rules):
        """
        Download the collection rules gpg signature
        """
        sig_text = self.fetch_gpg()
        sig_response = NamedTemporaryFile(suffix=".asc")
        sig_response.write(sig_text)
        sig_response.file.flush()
        self.validate_gpg_sig(collection_rules.name, sig_response.name)
        self.write_collection_data(self.collection_rules_file + ".asc", sig_text)

    def write_collection_data(self, path, data):
        """
        Write collections rules to disk
        """
        dyn_conf_file = os.fdopen(os.open(path,
                                          os.O_WRONLY | os.O_CREAT,
                                          int("0600", 8)), 'w')
        dyn_conf_file.write(data)
        dyn_conf_file.close()

    def get_conf(self, update, stdin_config=None):
        """
        Get the config
        """
        rm_conf = None
        # Convert config object into dict
        if os.path.isfile(self.remove_file):
            from ConfigParser import RawConfigParser
            parsedconfig = RawConfigParser()
            parsedconfig.read(self.remove_file)
            rm_conf = {}
            for item, value in parsedconfig.items('remove'):
                rm_conf[item] = value.strip().split(',')
            logger.warn("WARNING: Excluding data from files")
        if stdin_config:
            rules_fp = NamedTemporaryFile(delete=False)
            rules_fp.write(stdin_config["uploader.json"])
            rules_fp.flush()
            sig_fp = NamedTemporaryFile(delete=False)
            sig_fp.write(stdin_config["sig"])
            sig_fp.flush()
            if not self.gpg or self.validate_gpg_sig(rules_fp.name, sig_fp.name):
                return json.loads(stdin_config["uploader.json"]), rm_conf
            else:
                logger.error("Unable to validate GPG signature in from_stdin mode.")
                raise Exception("from_stdin mode failed to validate GPG sig")
        elif update:
            if not self.conn:
                logger.error('ERROR: Cannot update rules in --offline mode. '
                             'Either run without the --update-collection-rules '
                             'option or disable auto_update in config file.')
                sys.exit(1)
            dyn_conf = self.get_collection_rules()
            version = dyn_conf.get('version', None)
            if version is None:
                logger.error("ERROR: Could not find version in json")
                sys.exit(1)
            dyn_conf['file'] = self.collection_rules_file
            logger.debug("Success reading config")
            logger.debug(json.dumps(dyn_conf))
            return dyn_conf, rm_conf
        else:
            for conf_file in [self.collection_rules_file, self.fallback_file]:
                logger.debug("trying to read conf from: " + conf_file)
                conf = self.try_disk(conf_file, self.gpg)
                if conf:
                    version = conf.get('version', None)
                    if version is None:
                        logger.error("ERROR: Could not find version in json")
                        sys.exit(1)

                    conf['file'] = conf_file
                    logger.debug("Success reading config")
                    logger.debug(json.dumps(conf))
                    return conf, rm_conf
        logger.error("ERROR: Unable to download conf or read it from disk!")
        sys.exit(1)
