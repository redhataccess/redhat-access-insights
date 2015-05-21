"""
Collect all the interesting data for analysis
"""
import os
import re
from subprocess import Popen, PIPE, STDOUT
import errno
import shlex
import json
import archive
import logging
import six
from tempfile import NamedTemporaryFile
from soscleaner import SOSCleaner
from utilities import determine_hostname, _expand_paths, write_file_with_text
from constants import InsightsConstants as constants

APP_NAME = constants.app_name
logger = logging.getLogger(APP_NAME)
# python 2.7
SOSCLEANER_LOGGER = logging.getLogger('soscleaner')
SOSCLEANER_LOGGER.setLevel(logging.ERROR)
# python 2.6
SOSCLEANER_LOGGER = logging.getLogger('redhat_access_insights.soscleaner')
SOSCLEANER_LOGGER.setLevel(logging.ERROR)


class DataCollector(object):
    """
    Run commands and collect files
    """

    def __init__(self):
        self._set_black_list()
        self.archive = archive.InsightsArchive()

    def _set_black_list(self):
        """
        Never run these commands
        """
        self.black_list = ["rm", "kill", "reboot", "shutdown"]

    def _mangle_command(self, command, name_max=255):
        """
        Mangle the command name, lifted from sos
        """
        mangledname = re.sub(r"^/(usr/|)(bin|sbin)/", "", command)
        mangledname = re.sub(r"[^\w\-\.\/]+", "_", mangledname)
        mangledname = re.sub(r"/", ".", mangledname).strip(" ._-")
        mangledname = mangledname[0:name_max]
        return mangledname

    def run_command_get_output(self,
                               command,
                               exclude=None,
                               filters=None,
                               nolog=False):
        """
        Execute a command through the system shell. First checks to see if the
        requested command is executable. Returns (returncode, stdout, 0)
        """
        cmd_env = os.environ
        # ensure consistent locale for collected command output
        cmd_env['LC_ALL'] = 'C'
        if not six.PY3:
            command = command.encode('utf-8', 'ignore')
        args = shlex.split(command)
        if set.intersection(set(args), set(self.black_list)):
            raise RuntimeError("Command Blacklist")
        try:
            if not nolog:
                logger.debug("Executing: %s", args)
            proc0 = Popen(args, shell=False, stdout=PIPE, stderr=STDOUT,
                          bufsize=-1, env=cmd_env, close_fds=True)
        except OSError as err:
            if err.errno == errno.ENOENT:
                logger.debug("Command %s not found", command)
                return {'cmd': self._mangle_command(command),
                        'status': 127,
                        'output': "Command not found"}
            else:
                raise err

        dirty = False

        if exclude is not None:
            exclude_file = NamedTemporaryFile()
            exclude_file.write("\n".join(exclude))
            exclude_file.flush()
            cmd = "/bin/grep -F -v -f %s" % exclude_file.name
            proc1 = Popen(shlex.split(cmd.encode("utf-8")),
                          stdin=proc0.stdout,
                          stdout=PIPE)
            proc0.stdout.close()
            if filters is None or len(filters) == 0:
                stdout, stderr = proc1.communicate()
            proc0 = proc1
            dirty = True

        if filters is not None and len(filters):
            pattern_file = NamedTemporaryFile()
            pattern_file.write("\n".join(filters))
            pattern_file.flush()
            cmd = "/bin/grep -F -f %s" % pattern_file.name
            proc2 = Popen(shlex.split(cmd.encode("utf-8")),
                          stdin=proc0.stdout,
                          stdout=PIPE)
            proc0.stdout.close()
            stdout, stderr = proc2.communicate()
            dirty = True

        if not dirty:
            stdout, stderr = proc0.communicate()

        # Required hack while we still pass shell=True to Popen; a Popen
        # call with shell=False for a non-existant binary will raise OSError.
        if proc0.returncode == 126 or proc0.returncode == 127:
            stdout = "Could not find cmd: %s" % command

        logger.debug("Status: %s", proc0.returncode)
        logger.debug("stderr: %s", stderr)

        return {
            'cmd': self._mangle_command(command),
            'status': proc0.returncode,
            'output': stdout.decode('utf-8', 'ignore')
        }

    def run_commands(self, conf, rm_conf):
        """
        Run through the list of commands and add them to the archive
        """
        logger.debug("Beginning to execute commands")
        if rm_conf is not None:
            try:
                exclude = rm_conf['patterns']
            except LookupError:
                exclude = None
        else:
            exclude = None

        commands = conf['commands']
        for command in commands:
            if rm_conf:
                try:
                    if command['command'] in rm_conf['commands']:
                        logger.warn("WARNING: Skipping command %s", command['command'])
                        continue
                except LookupError:
                    pass

            if 'ethtool' in command['command']:
                # Get the ethtool flag
                flag = None
                try:
                    flag = command['command'].split('-')[1]
                except LookupError:
                    pass
                self._handle_ethtool(flag)
            elif 'hostname' in command['command']:
                self._handle_hostname(command['command'])
            elif 'modinfo' in command['command']:
                self._handle_modinfo()
            elif len(command['pattern']) or exclude:
                cmd = command['command']
                filters = command['pattern']
                output = self.run_command_get_output(cmd, filters=filters, exclude=exclude)
                self.archive.add_command_output(output)
            else:
                self.archive.add_command_output(
                    self.run_command_get_output(command['command']))
        logger.debug("Commands complete")

    def _get_interfaces(self):
        """
        Get valid ethernet interfaces on the system
        """
        interfaces = {}
        output = self.run_command_get_output(
            "/sbin/ip -o link")["output"].splitlines()
        for line in output:
            match = re.match(
                '.*link/ether', line.decode('utf-8', 'ignore').strip())
            if match:
                iface = match.string.split(':')[1].lstrip()
                interfaces[iface] = True
        return interfaces

    def _handle_modinfo(self):
        """
        Helper to handle modinfo
        """
        for module in os.listdir("/sys/module"):
            response = self.run_command_get_output("modinfo " + module)
            if response['status'] is 0:
                self.archive.add_command_output(response)
            else:
                logger.debug("Module %s not loaded; skipping", module)

    def _handle_hostname(self, command):
        """
        Helper to attempt to get fqdn as hostname
        """
        self.archive.add_command_output({
            'cmd': self._mangle_command(command),
            'status': 0,
            'output': determine_hostname()
        })

    def _handle_ethtool(self, flag):
        """
        Helper to handle ethtool not supporting *
        """
        for interface in self._get_interfaces():
            if flag is not None:
                cmd = "/sbin/ethtool -" + flag + " " + interface
            else:
                cmd = "/sbin/ethtool " + interface
            self.archive.add_command_output(self.run_command_get_output(cmd))

    def copy_files(self, conf, rm_conf):
        """
        Run through the list of files and copy them
        """
        logger.debug("Beginning to copy files")
        files = conf['files']
        if rm_conf:
            try:
                exclude = rm_conf['patterns']
            except LookupError:
                exclude = None
        else:
            exclude = None

        for _file in files:
            if rm_conf:
                try:
                    if _file['file'] in rm_conf['files']:
                        logger.warn("WARNING: Skipping file %s", _file['file'])
                        continue
                except LookupError:
                    pass

            pattern = None
            if len(_file['pattern']) > 0:
                pattern = _file['pattern']

            if pattern is None and exclude is None:
                self.archive.copy_file(_file['file'])
            else:
                self.copy_file_with_pattern(_file['file'], pattern, exclude)
        logger.debug("File copy complete")

    def write_branch_info(self, branch_info):
        """
        Write branch information to file
        """
        logger.debug("Writing branch information to workdir")
        full_path = self.archive.get_full_archive_path('/branch_info')
        write_file_with_text(full_path, json.dumps(branch_info))

    def _copy_file_with_pattern(self, path, patterns, exclude):
        """
        Copy file, selecting only lines we are interested in
        """
        full_path = self.archive.get_full_archive_path(path)
        if not os.path.isfile(path):
            logger.debug("File %s does not exist", path)
            return
        logger.debug("Copying %s to %s with filters %s", path, full_path, str(patterns))
        stdin = None
        if exclude is not None:
            exclude_file = NamedTemporaryFile()
            exclude_file.write("\n".join(exclude))
            exclude_file.flush()

            cmd = "/bin/grep -v -F -f %s %s" % (exclude_file.name, path)
            args = shlex.split(cmd.encode("utf-8"))
            proc = Popen(args, stdout=PIPE)
            stdin = proc.stdout
            if patterns is None:
                output = proc.communicate()[0]

        if patterns is not None:
            pattern_file = NamedTemporaryFile()
            pattern_file.write("\n".join(patterns))
            pattern_file.flush()

            if exclude is None:
                cmd = "/bin/grep -F -f %s %s" % (pattern_file.name, path)
            else:
                cmd = "/bin/grep -F -f %s" % pattern_file.name
            args = shlex.split(cmd.encode("utf-8"))
            proc1 = Popen(args, stdin=stdin, stdout=PIPE)

            if exclude is not None:
                stdin.close()

            output = proc1.communicate()[0]

        write_file_with_text(full_path, output)

    def copy_file_with_pattern(self, path, patterns, exclude):
        """
        Copy a single file or regex, creating the necessary directories
        But grepping for pattern(s)
        """
        if "*" in path:
            paths = _expand_paths(path)
            if not paths:
                logger.debug("Could not expand %s", path)
                return
            for path in paths:
                self._copy_file_with_pattern(path, patterns, exclude)
        else:
            self._copy_file_with_pattern(path, patterns, exclude)

    def done(self, config, rm_conf):
        """
        Do finalization stuff
        """
        if config.getboolean(APP_NAME, "obfuscate"):
            cleaner = SOSCleaner(quiet=True)
            clean_opts = CleanOptions(self.archive.tmp_dir, config, rm_conf)
            fresh = cleaner.clean_report(clean_opts, self.archive.archive_dir)
            if clean_opts.keyword_file is not None:
                os.remove(clean_opts.keyword_file.name)
            return fresh[0]
        return self.archive.create_tar_file()


class CleanOptions(object):
    """
    Options for soscleaner
    """
    def __init__(self, tmp_dir, config, rm_conf):
        self.report_dir = tmp_dir
        self.domains = []
        self.files = []
        self.quiet = True
        self.keyword_file = None
        self.keywords = None

        if rm_conf:
            try:
                keywords = rm_conf['keywords']
                self.keyword_file = NamedTemporaryFile(delete=False)
                self.keyword_file.write("\n".join(keywords))
                self.keyword_file.flush()
                self.keyword_file.close()
                self.keywords = [self.keyword_file.name]
                logger.debug("Attmpting keyword obfuscation")
            except LookupError:
                pass

        if config.getboolean(APP_NAME, "obfuscate_hostname"):
            self.hostname_path = "insights_commands/hostname"
        else:
            self.hostname_path = None
