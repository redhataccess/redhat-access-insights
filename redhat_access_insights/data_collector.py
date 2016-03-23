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


"""

An example additions to uploader.json

    "specs": {
        ...
        "rpm_-V_packages": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/rpm -V coreutils procps procps-ng shadow-utils passwd sudo",
                    "archive_file_name": "/insights_commands/rpm_-V_coreutils_procps_procps-ng_shadow-utils_passwd_sudo"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/bin/rpm --root={CONTAINER_MOUNT_POINT} -V coreutils procps procps-ng shadow-utils passwd sudo",
                    "archive_file_name": "/insights_data/image/commands/rpm_-V_coreutils_procps_procps-ng_shadow-utils_passwd_sudo"
                }
            ]
        },
        "httpd.conf": {
            "host": [
                {
                    "pattern": [
                        "SSLProtocol",
                        "SSLCipherSuite",
                        "NSSProtocol"
                    ],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/etc/httpd/conf/httpd.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "SSLProtocol",
                        "SSLCipherSuite",
                        "NSSProtocol"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/httpd/conf/httpd.conf"
                }
            ]
        },
        ...

    "specs" is a new top level section combining the function of both the existing sections "commands"
    and "files".

    "httpd.conf" and "rpm_-V_packages" are the symbolic names of two specs we can collect.

    "host" and "docker_image" are analysis targets.  The "host" section should directly echo
    the "commands" and "files" sections in the same file.

     "file" and "command" have the same meanings as they do in the existing "files" and "commands"
     sections, with the exception that they may now contain symbolic names of things only the
     client can determine.

     "archive_file_name" is the location where the output of this spec should be located for
     this analysis target.  It may contain symbolic names.


     "{CONTAINER_MOUNT_POINT}" only defined in "file" and "command", for docker_container and
     docker_image, the location on the host where the root file system of the container or image
     is mounted.

     "{EXPANDED_FILE_NAME}" only defined in "archive_file_name" in sections also containing "file".
     Since "file" can contain a pattern, and can collect multiple files with names not known till
     collected, this provides a way to place these files in the archive.  If "file" contains
     "{CONTAINER_MOUNT_POINT}" it will not be included in the expansion of "{EXPADED_FILE_NAME}".

"""


#
# The collection rules have some optional stuff in them now, so the following simplify indexing
# into dictionaries that might not have the indexes that you are looking for.
#
# so for example you want to write:
#
#    foo = d['meta_specs']['uploader_log']['something_else']
#
# but d might not have 'meta_specs' and that might not have 'uploader_log' and ...
# so write this instead
#
#   idx = ('meta_specs','uploader_log','something_else')
#   if dictmultihas(d, idx):
#      foo = dictmultiget(d, idx)
#   else:
#      ....
#

def dictmultihas(d, idx):
    # 'idx' is a tuple of strings, indexing into 'd'
    #  if d doesn't have these indexes, return False
    for each in idx[:-1]:
        if d and each in d:
            d = d[each]
    if d and len(idx) > 0 and idx[-1] in d:
        return True
    else:
        return False

def dictmultiget(d, idx):
    # 'idx' is a tuple of strings, indexing into 'd'
    for each in idx[:-1]:
        d = d[each]
    return d[idx[-1]]




class DataCollector(object):
    """
    Run commands and collect files
    """

    def __init__(self, archive_=None):
        self._set_black_list()
        self.archive = archive_ if archive_ else archive.InsightsArchive()

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
                               nolog=False,
                               mangled_command=None):
        """
        Execute a command through the system shell. First checks to see if the
        requested command is executable. Returns (returncode, stdout, 0)
        """

        if mangled_command == None:
            mangled_command = self._mangle_command(command)

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
                return {'cmd': mangled_command,
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
            'cmd': mangled_command,
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
                    if command['command'] in rm_conf['commands']:
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
            if _file['file'] == '/etc/redhat-access-insights/machine-id' and stdin_config:
                try:
                    machine_id = stdin_config['machine-id']
                    logger.debug('Using machine-id from stdin: %s' % machine_id)
                    write_file_with_text(
                        self.archive.get_full_archive_path(_file['file']),
                        machine_id)
                    continue
                except KeyError:
                    logger.debug('No machine-id from stdin.  Using regular file')
            self.copy_file_with_pattern(_file['file'], pattern, exclude)
        logger.debug("File copy complete")

    def write_branch_info(self, branch_info, collection_rules=None):
        """
        Write branch information to file
        collection_rules is None if we are doing a VERSION0 collection
        """

        idx = ('meta_specs','branch_info','archive_file_name')
        if not dictmultihas(collection_rules, idx):
            branch_info_location = '/branch_info'
        else:
            branch_info_location = dictmultiget(collection_rules, idx)

        logger.debug("Writing branch information to workdir")
        full_path = self.archive.get_full_archive_path(branch_info_location)
        write_file_with_text(full_path, json.dumps(branch_info))

    def write_analysis_target(self, analysis_target, collection_rules):
        idx = ('meta_specs','analysis_target','archive_file_name')
        if dictmultihas(collection_rules, idx):
            analysis_target_location = dictmultiget(collection_rules, idx)
            logger.debug("Writing analysis_target, '%s' information to: %s" % (analysis_target, analysis_target_location))
            full_path = self.archive.get_full_archive_path(analysis_target_location)
            write_file_with_text(full_path, analysis_target)

    def write_machine_id(self, machine_id, collection_rules):
        idx = ('meta_specs','machine-id','archive_file_name')
        if dictmultihas(collection_rules, idx):
            machine_id_location = dictmultiget(collection_rules, idx)
            logger.debug("Writing machine_id, '%s' information to: %s" % (machine_id, machine_id_location))
            full_path = self.archive.get_full_archive_path(machine_id_location)
            write_file_with_text(full_path, machine_id)

    def _copy_file_with_pattern(self, path_on_disk, patterns, exclude,
                                container_fs=None,
                                archive_file_name=None):
        """
        Copy path_on_disk into archive, selecting only lines we are interested in

        path_on_disk is the full path of the file to copy.
            If the file is within a mounted file system, then container_fs will not
            be None, and will be the initial part of path_on_disk, this is done so
            that _expand_files works correctly for mounted file systems.
        container_fs: if not None, is the absolute file name of the mounted file system
        archive_file_name: if not None, is a where in the archive that path_on_disk should
            be copied.  This may contain '{EXPANDED_FILE_NAME}' which will be replaced
            by the value of path_on_disk with the value of container_fs removed.
        """
        if not os.path.isfile(path_on_disk):
            logger.debug("File %s does not exist", path_on_disk)
            return

        if container_fs:
            # reconstruct the path_to_collect by stripping off the container
            path_to_collect = '/' + os.path.relpath(path_on_disk, container_fs)
        else:
            path_to_collect = path_on_disk

        if archive_file_name:
            path_in_archive = self.archive.get_full_archive_path(
                archive_file_name.replace("{EXPANDED_FILE_NAME}", path_to_collect))
        else:
            path_in_archive = self.archive.get_full_archive_path(path_to_collect)

        logger.debug("Copying %s to %s with filters %s", path_on_disk, path_in_archive, str(patterns))

        cmd = []
        # shlex.split doesn't handle special characters well
        cmd.append("/bin/sed".encode('utf-8'))
        cmd.append("-rf".encode('utf-8'))
        cmd.append(constants.default_sed_file.encode('utf-8'))
        cmd.append(path_on_disk.encode('utf8'))
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

        write_file_with_text(path_in_archive, output.decode('utf-8', 'ignore').strip())

    def copy_file_with_pattern(self, paths_to_collect, patterns, exclude,
                               container_fs=None,
                               archive_file_name=None):
        """
        Copy a single file or regex, creating the necessary directories
        But grepping for pattern(s)
        """
        if "*" in paths_to_collect:
            paths = _expand_paths(paths_to_collect)
            if not paths:
                logger.debug("Could not expand %s", paths_to_collect)
                return
            for path_on_disk in paths:
                self._copy_file_with_pattern(path_on_disk, patterns, exclude,
                                             container_fs=container_fs,
                                             archive_file_name=archive_file_name)
        else:
            self._copy_file_with_pattern(paths_to_collect, patterns, exclude,
                                         container_fs=container_fs,
                                         archive_file_name=archive_file_name)


    def _process_file_spec(self, spec, exclude, options):

        pattern = None
        if len(spec['pattern']) > 0:
            pattern = spec['pattern']

        if 'archive_file_name' in spec:
            archive_file_name = spec['archive_file_name']
        else:
            archive_file_name = None

        if options.container_fs:
            files_to_collect = spec['file'].replace("{CONTAINER_MOUNT_POINT}", options.container_fs)
        else:
            files_to_collect = spec['file']

        self.copy_file_with_pattern(files_to_collect, pattern, exclude,
                                    options.container_fs,
                                    archive_file_name=archive_file_name)


    def _process_command_spec(self, spec, exclude, options):

        if options.collection_target == "host":
            self._handle_commands(spec, exclude)

        else:
            if options.container_fs:
                command = spec['command'].replace("{CONTAINER_MOUNT_POINT}", options.container_fs)

            filters = spec['pattern']

            if 'archive_file_name' in spec:
                archive_file_name = spec['archive_file_name']
                mangled_command = None
            else:
                archive_file_name = None
                mangled_command = self._mangle_command(specs['command'])

            output = self.run_command_get_output(command, filters=filters, exclude=exclude,
                                                 mangled_command=mangled_command)
            self.archive.add_command_output(output, archive_file_name=archive_file_name)

    def process_specs(self, conf, rm_conf, options):
        logger.debug("Beginning to process specs")

        if rm_conf:
            try:
                exclude = rm_conf['patterns']
            except LookupError:
                exclude = None
        else:
            exclude = None

        for name, spec_group in conf['specs'].items():
            if options.collection_target in spec_group:
                for each_spec in spec_group[options.collection_target]:
                    if 'file' in each_spec:
                        if rm_conf:
                            try:
                                if each_spec['file'] in rm_conf['files']:
                                    logger.warn("WARNING: Skipping file %s", each_spec['file'])
                                    continue
                            except LookupError:
                                pass

                        self._process_file_spec(each_spec, exclude, options)

                    elif 'command' in each_spec:
                        if rm_conf:
                            try:
                                if each_spec['command'] in rm_conf['commands']:
                                    logger.warn("WARNING: Skipping command %s", each_spec['command'])
                                    continue
                            except LookupError:
                                pass

                        self._process_command_spec(each_spec, exclude, options)

        logger.debug("specs processing complete")

    def done(self, config, rm_conf, collection_rules=None):
        """
        Do finalization stuff
        """

        # Only copy the log after all else is copied
        # collection_rules is None if we are doing an old style "VERSION0" collection
        idx = ('meta_specs', 'uploader_log')
        if dictmultihas(collection_rules, idx):
            path_in_archive = self.archive.get_full_archive_path(dictmultiget(collection_rules, idx)['archive_file_name'])
            content = open("/var/log/redhat-access-insights/redhat-access-insights.log").read().strip()
            write_file_with_text(path_in_archive, content.decode('utf-8', 'ignore'))

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
