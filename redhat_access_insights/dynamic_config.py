"""
Dynamic configuration for data collection
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

APP_NAME = constants.app_name
logger = logging.getLogger(APP_NAME)


class InsightsConfig(object):
    """
    Insights configuration
    """

    def __init__(self, config, conn):
        """
        Load config from parent
        """
        self.fallback_file = constants.dynamic_fallback_file
        self.remove_file = constants.dynamic_remove_file
        self.dynamic_config_file = constants.dynamic_conf_file
        self.dynamic_config_url = config.get(APP_NAME, 'dynamic_config_url')
        self.gpg = config.getboolean(APP_NAME, 'gpg')
        self.conn = conn

    def validate_gpg_sig(self, path, sig=None):
        """
        Validate the dynamic configuration
        """
        logger.info("Attempting to verify gpg "
                    "signature of Insights configuration")
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
            sys.exit("Unable to validate gpg signature! Exiting!")
        else:
            logger.info("gpg signature verified")
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
                    logger.error("Invalid JSON in %s", path)
                    sys.exit(1)
            else:
                logger.warn("WARNING: %s was an empty file", path)
                return

    def get_conf(self, update):
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
            try:
                patterns = rm_conf['patterns']
                logger.warn("WARNING: Excluding data from files")
            except LookupError:
                pass

        if update:
            logger.info("Attemping to download dynamic configuration from %s",
                        self.dynamic_config_url)

            req = self.conn.session.get(
                self.dynamic_config_url, headers=({'accept': 'text/plain'}))

            logger.info("Attemping to download dynamic "
                        "configuration GPG sig from %s",
                        self.dynamic_config_url + ".asc")

            headers = ({'accept': 'text/plain'})
            config_sig = self.conn.session.get(self.dynamic_config_url + '.asc',
                                               headers=headers)

            if req.status_code == 200 and config_sig.status_code == 200:
                logger.info("Successfully downloaded dynamic "
                            "configuration and signature")

                json_response = NamedTemporaryFile()
                json_response.write(req.text)
                json_response.file.flush()
                sig_response = NamedTemporaryFile(suffix=".asc")
                sig_response.write(config_sig.text)
                sig_response.file.flush()
                self.validate_gpg_sig(json_response.name, sig_response.name)

                dyn_conf = json.loads(req.text)
                # Ensure that we have JSON
                if dyn_conf:
                    try:
                        dyn_conf['version']
                        dyn_conf_file = os.fdopen(os.open(self.dynamic_config_file,
                                                          os.O_WRONLY | os.O_CREAT,
                                                          int("0600", 8)), 'w')
                        dyn_conf_file.write(req.text)
                        dyn_conf_file.close()
                        dyn_conf_sig_file = os.fdopen(os.open(self.dynamic_config_file + ".asc",
                                                              os.O_WRONLY | os.O_CREAT,
                                                              int("0600", 8)), 'w')
                        dyn_conf_sig_file.write(config_sig.text)
                        dyn_conf_sig_file.close()
                        dyn_conf['file'] = self.dynamic_config_file
                        logger.debug("Success reading config")
                        logger.debug(json.dumps(dyn_conf))
                        return dyn_conf, rm_conf
                    except LookupError:
                        logger.error("Could not parse json from remote host")
            else:
                logger.error("Could not download dyanmic configuration")
                logger.error("Conf status: %s", req.status_code)
                logger.error("Sig status: %s", config_sig.status_code)

        for conf_file in [self.dynamic_config_file, self.fallback_file]:
            logger.debug("trying to read conf from: " + conf_file)
            conf = self.try_disk(conf_file, self.gpg)
            if conf:
                try:
                    conf['version']
                    conf['file'] = conf_file
                    logger.debug("Success reading config")
                    logger.debug(json.dumps(conf))
                    return conf, rm_conf
                except LookupError:
                    logger.debug("Failed to find version")

        raise Exception("Unable to download conf or read it from disk!")
