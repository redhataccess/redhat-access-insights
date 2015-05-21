"""
Utility functions
"""
import socket
import shlex
import os
import sys
import logging
import uuid
from subprocess import Popen, PIPE
from constants import InsightsConstants as constants

logger = logging.getLogger(constants.app_name)


def determine_hostname():
    """
    Find fqdn if we can
    """
    socket_gethostname = socket.gethostname()
    socket_fqdn = socket.getfqdn()

    try:
        socket_ex = socket.gethostbyname_ex(socket_gethostname)[0]
    except LookupError:
        socket_ex = ''
    except socket.gaierror:
        socket_ex = ''

    gethostname_len = len(socket_gethostname)
    fqdn_len = len(socket_fqdn)
    ex_len = len(socket_ex)

    if fqdn_len > gethostname_len or ex_len > gethostname_len:
        if "localhost" not in socket_ex:
            return socket_ex
        if "localhost" not in socket_fqdn:
            return socket_fqdn

    return socket_gethostname


def _write_machine_id(machine_id):
    """
    Write machine id out to disk
    """
    logger.debug("Creating %s", constants.machine_id_file)
    machine_id_file = open(constants.machine_id_file, "w")
    machine_id_file.write(machine_id)
    machine_id_file.flush()
    machine_id_file.close()


def write_unregistered_file(date):
    """
    Write .unregistered out to disk
    """
    unreg = file(constants.unregistered_file, 'w')
    unreg.write(str(date))
    logger.error("This machine has been unregistered")
    logger.error("Use --register if you would like to re-register this machine")
    logger.error("Exiting")
    sys.exit(1)


def delete_unregistered_file():
    """
    Remove the .unregistered file if we are doing a register
    """
    if os.path.isfile(constants.unregistered_file):
        os.remove(constants.unregistered_file)


def generate_machine_id(new=False):
    """
    Generate a machine-id if /etc/machine-id does not exist
    """
    machine_id = None
    machine_id_file = None
    if os.path.isfile(constants.machine_id_file) and not new:
        logger.debug('Found %s', constants.machine_id_file)
        machine_id_file = open(constants.machine_id_file, 'r')
        machine_id = machine_id_file.read()
        machine_id_file.close()
    elif (os.path.isfile('/etc/machine-id') and not
          os.path.isfile(constants.machine_id_file)):
        logger.debug('Found /etc/machine-id, '
                     'but not %s', constants.machine_id_file)
        machine_id_file = open("/etc/machine-id", "r")
        machine_id = machine_id_file.read()
        machine_id_file.close()
        _write_machine_id(machine_id)
    elif ((not os.path.isfile('/etc/machine-id') and not
           os.path.isfile(constants.machine_id_file)) or
          new):
        logger.debug('Could not find machine-id file, creating')
        machine_id = str(uuid.uuid4())
        _write_machine_id(machine_id)
    return str(machine_id).strip()


def _expand_paths(path):
    """
    Expand wildcarded paths
    """
    import re
    dir_name = os.path.dirname(path)
    paths = []
    logger.debug("Attempting to expand %s", path)
    if os.path.isdir(dir_name):
        files = os.listdir(dir_name)
        match = os.path.basename(path)
        for file_path in files:
            if re.match(match, file_path):
                expanded_path = os.path.join(dir_name, file_path)
                paths.append(expanded_path)
        logger.debug("Expanded paths %s", paths)
        return paths
    else:
        logger.debug("Could not expand %s", path)


def write_file_with_text(path, text):
    """
    Write to file with text
    """
    try:
        os.makedirs(os.path.dirname(path))
    except OSError:
        logger.debug("Could not create dir for %s", os.path.dirname(path))

    file_from_text = open(path, 'w')
    file_from_text.write(text.encode('utf8'))
    file_from_text.close()


def validate_remove_file():
    """
    Validate the remove file
    """
    import stat
    if not os.path.isfile(constants.dynamic_remove_file):
        sys.exit("Remove file does not exist")
    # Make sure permissions are 600
    mode = stat.S_IMODE(os.stat(constants.dynamic_remove_file).st_mode)
    if not mode == 0o600:
        sys.exit("Invalid remove file permissions"
                 "Expected 0600 got %s" % oct(mode))
    else:
        print "Correct file permissions"

    if os.path.isfile(constants.dynamic_remove_file):
        from ConfigParser import RawConfigParser
        parsedconfig = RawConfigParser()
        parsedconfig.read(constants.dynamic_remove_file)
        rm_conf = {}
        for item, value in parsedconfig.items('remove'):
            rm_conf[item] = value.strip().split(',')
        print "Remove file parsed contents"
        print rm_conf
    logger.info("JSON parsed correctly")
