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
import glob
import copy
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

    def __init__(self, archive_=None, config=None):
        self._set_black_list()
        self.archive = archive_ if archive_ else archive.InsightsArchive()
        self.config = config

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
        # add a default command timeout
        # get this from the configuration file if it exists
        if self.config and self.config.has_option(APP_NAME, 'cmd_timeout'):
            cmd_timeout = self.config.getint(APP_NAME, 'cmd_timeout')
        else:
            cmd_timeout = constants.default_cmd_timeout
        # ensure consistent locale for collected command output
        cmd_env = {'LC_ALL': 'C'}
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

        cmd = "/bin/sed -rf " + constants.default_sed_file
        sedcmd = Popen(shlex.split(cmd.encode('utf-8')),
                       stdin=proc0.stdout,
                       stdout=PIPE)
        proc0.stdout.close()
        proc0 = sedcmd

        from threading import Timer

        def kill_proc(p):
            p.kill()

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
                timer1 = Timer(cmd_timeout, kill_proc, [proc1])
                try:
                    timer1.start()
                    stdout, stderr = proc1.communicate()
                finally:
                    if not timer1.is_alive():
                        logger.debug('Command %s took too long to run. Exiting.', command)
                        return {'cmd': self._mangle_command(command),
                                'status': 130,
                                'output': 'Command took to long to run. Exiting.'}
                    timer1.cancel()
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
            timer2 = Timer(cmd_timeout, kill_proc, [proc2])
            try:
                timer2.start()
                stdout, stderr = proc2.communicate()
            finally:
                if not timer2.is_alive():
                    logger.debug('Command %s took too long to run. Exiting.', command)
                    return {'cmd': self._mangle_command(command),
                            'status': 130,
                            'output': 'Command took to long to run. Exiting.'}
                timer2.cancel()
            dirty = True

        if not dirty:
            timer0 = Timer(cmd_timeout, kill_proc, [proc0])
            try:
                timer0.start()
                stdout, stderr = proc0.communicate()
            finally:
                if not timer0.is_alive():
                    logger.debug('Command %s took too long to run. Exiting.', command)
                    return {'cmd': self._mangle_command(command),
                            'status': 130,
                            'output': 'Command took to long to run. Exiting.'}
                timer0.cancel()

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

    def _handle_commands(self, command, exclude):
        """
        Handle special commands
        """
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
        elif 'parted' in command['command']:
            self._handle_parted()
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
                    if 'commands' in rm_conf and command['command'] in rm_conf['commands']:
                        logger.warn("WARNING: Skipping command %s", command['command'])
                        continue
                except LookupError:
                    pass

            self._handle_commands(command, exclude)

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

    def _handle_parted(self):
        """
        Helper to handle parted
        """
        if os.path.isdir("/sys/block"):
            for disk in os.listdir("/sys/block"):
                if disk in ['.', '..'] or disk.startswith('ram'):
                    continue
                disk_path = os.path.join('/dev/', disk)
                self.archive.add_command_output(
                    self.run_command_get_output("/usr/sbin/parted -s %s unit s print" % disk_path))

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

    def copy_files(self, conf, rm_conf, stdin_config=None):
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
            # Do some things with globs
            if 'glob' in _file:
                # Get all of the files using the glob
                glob_files = glob.glob(_file['glob'])
                if glob_files:
                    for glob_file_name in glob_files:
                        a_new_file = copy.copy(_file)  # copy the current file structure
                        a_new_file['file'] = glob_file_name  # update the file name with the found glob file name
                        self._check_file(a_new_file, rm_conf, exclude, stdin_config)  # shoosh it through
                else:
                    continue
            # Do some things with files
            elif 'file' in _file:
                self._check_file(_file, rm_conf, exclude, stdin_config)

        logger.debug("File copy complete")

    def _check_file(self, the_file, rm_conf, exclude, stdin_config):
        '''
        Check file used to check if a file is in the remove conf
        Otherwise copy the file
        '''
        if rm_conf:
            try:
                if 'files' in rm_conf and the_file['file'] in rm_conf['files']:
                    logger.warn("WARNING: Skipping file %s", the_file['file'])
                    return
            except LookupError:
                pass

        pattern = None
        if len(the_file['pattern']) > 0:
            pattern = the_file['pattern']
        if the_file['file'] == '/etc/redhat-access-insights/machine-id' and stdin_config:
            try:
                machine_id = stdin_config['machine-id']
                logger.debug('Using machine-id from stdin: %s' % machine_id)
                write_file_with_text(
                    self.archive.get_full_archive_path(the_file['file']),
                    machine_id)
                return
            except KeyError:
                logger.debug('No machine-id from stdin.  Using regular file')
        self.copy_file_with_pattern(the_file['file'], pattern, exclude)

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

        cmd = []
        # shlex.split doesn't handle special characters well
        cmd.append("/bin/sed".encode('utf-8'))
        cmd.append("-rf".encode('utf-8'))
        cmd.append(constants.default_sed_file.encode('utf-8'))
        cmd.append(path.encode('utf8'))
        sedcmd = Popen(cmd,
                       stdout=PIPE)

        if exclude is not None:
            exclude_file = NamedTemporaryFile()
            exclude_file.write("\n".join(exclude))
            exclude_file.flush()

            cmd = "/bin/grep -v -F -f %s" % exclude_file.name
            args = shlex.split(cmd.encode("utf-8"))
            proc = Popen(args, stdin=sedcmd.stdout, stdout=PIPE)
            sedcmd.stdout.close()
            stdin = proc.stdout
            if patterns is None:
                output = proc.communicate()[0]
            else:
                sedcmd = proc

        if patterns is not None:
            pattern_file = NamedTemporaryFile()
            pattern_file.write("\n".join(patterns))
            pattern_file.flush()

            cmd = "/bin/grep -F -f %s" % pattern_file.name
            args = shlex.split(cmd.encode("utf-8"))
            proc1 = Popen(args, stdin=sedcmd.stdout, stdout=PIPE)
            sedcmd.stdout.close()

            if exclude is not None:
                stdin.close()

            output = proc1.communicate()[0]

        if patterns is None and exclude is None:
            output = sedcmd.communicate()[0]

        write_file_with_text(full_path, output.decode('utf-8', 'ignore').strip())

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
