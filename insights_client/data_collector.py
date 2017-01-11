"""
Collect all the interesting data for analysis
"""
import os
import errno
import json
import archive
import logging
import copy
from subprocess import Popen, PIPE, STDOUT
from tempfile import NamedTemporaryFile
from soscleaner import SOSCleaner
from utilities import _expand_paths, generate_analysis_target_id
from constants import InsightsConstants as constants
from insights_spec import InsightsFile, InsightsCommand
from client_config import InsightsClient

APP_NAME = constants.app_name
logger = logging.getLogger(__name__)

# python 2.7
SOSCLEANER_LOGGER = logging.getLogger('soscleaner')
SOSCLEANER_LOGGER.setLevel(logging.ERROR)
# python 2.6
SOSCLEANER_LOGGER = logging.getLogger('insights-client.soscleaner')
SOSCLEANER_LOGGER.setLevel(logging.ERROR)


class DataCollector(object):
    '''
    Run commands and collect files
    '''
    def __init__(self, archive_=None, config=None, mountpoint=None, target_name='', target_type='host'):
        self.archive = archive_ if archive_ else archive.InsightsArchive()
        self.mountpoint = '/'
        if mountpoint:
            self.mountpoint = mountpoint
        self.target_name = target_name
        self.target_type = target_type
        self.config = config

    def _get_meta_path(self, specname, conf):
        # should really never need these
        #   since spec should always have an "archive_file_name"
        #   unless we are running old style spec
        default_meta_spec = {'analysis_target': '/insights_data/analysis_target',
                             'branch_info': '/branch_info',
                             'machine-id': '/insights_data/machine-id',
                             'uploader_log': '/insights_data/insights_logs/insights.log'}
        try:
            archive_path = conf['meta_specs'][specname]['archive_file_name']
        except LookupError:
            logger.debug('%s spec not found. Using default.', specname)
            archive_path = default_meta_spec[specname]
        return archive_path

    def _write_branch_info(self, conf, branch_info):
        logger.debug("Writing branch information to archive...")
        self.archive.add_metadata_to_archive(json.dumps(branch_info),
                                             self._get_meta_path('branch_info', conf))

    def _write_analysis_target_type(self, conf):
        logger.debug('Writing target type to archive...')
        self.archive.add_metadata_to_archive(self.target_type,
                                             self._get_meta_path('analysis_target', conf))

    def _write_analysis_target_id(self, conf):
        # AKA machine-id
        logger.debug('Writing machine-id to archive...')
        machine_id = generate_analysis_target_id(self.target_type, self.target_name)
        self.archive.add_metadata_to_archive(machine_id,
                                             self._get_meta_path('machine-id', conf))

    def _write_uploader_log(self, conf):
        logger.debug('Writing insights.log to archive...')
        with open(constants.default_log_file) as logfile:
            self.archive.add_metadata_to_archive(logfile.read().strip(),
                                                 self._get_meta_path('uploader_log', conf))

    def _run_pre_command(self, pre_cmd):
        '''
        Run a pre command to get external args for a command
        '''
        logger.debug('Executing pre-command: %s', pre_cmd)
        try:
            pre_proc = Popen(pre_cmd, stdout=PIPE, stderr=STDOUT, shell=True)
        except OSError as err:
            if err.errno == errno.ENOENT:
                logger.debug('Command %s not found', pre_cmd)
            return
        stdout, stderr = pre_proc.communicate()
        return stdout.splitlines()

    def _parse_file_spec(self, spec):
        '''
        Separate wildcard specs into more specs
        '''
        # separate wildcard specs into more specs
        if '*' in spec['file']:
            expanded_paths = _expand_paths(spec['file'].replace(
                '{CONTAINER_MOUNT_POINT}', self.mountpoint).replace(
                '{DOCKER_IMAGE_NAME}', self.target_name).replace(
                '{DOCKER_CONTAINER_NAME}', self.target_name))
            if not expanded_paths:
                return []

            expanded_specs = []
            for p in expanded_paths:
                _spec = copy.copy(spec)
                _spec['file'] = p
                expanded_specs.append(_spec)
            return expanded_specs

        else:
            return [spec]

    def _parse_glob_spec(self, spec):
        '''
        Grab globs of things
        '''
        import glob
        some_globs = glob.glob(spec['glob'])
        if not some_globs:
            return []
        el_globs = []
        for g in some_globs:
            _spec = copy.copy(spec)
            _spec['file'] = g
            el_globs.append(_spec)
        return el_globs

    def _parse_command_spec(self, spec, precmds):
        '''
        Run pre_commands
        '''
        if 'pre_command' in spec:
            precmd_alias = spec['pre_command']
            try:
                precmd = precmds[precmd_alias]
                args = self._run_pre_command(precmd)
                logger.debug('Pre-command results: %s', args)

                expanded_specs = []
                for arg in args:
                    _spec = copy.copy(spec)
                    _spec['command'] = _spec['command'] + ' ' + arg
                    expanded_specs.append(_spec)
                return expanded_specs
            except LookupError:
                logger.debug('Pre-command %s not found. Skipping %s...',
                             precmd_alias, spec['command'])
                return []
        else:
            return [spec]

    def _run_old_collection(self, conf, rm_conf, exclude, branch_info):
        # wrap old collection into specs for backward compatibility
        for f in conf['files']:
            if rm_conf and 'files' in rm_conf and f['file'] in rm_conf['files']:
                logger.warn("WARNING: Skipping file %s", f['file'])
                continue
            else:
                file_specs = self._parse_file_spec(f)
                for s in file_specs:
                    # spoof archive_file_name
                    # use _, archive path will be re-mangled anyway
                    s['archive_file_name'] = s['file']
                    file_spec = InsightsFile(s, exclude, self.mountpoint, self.target_name)
                    self.archive.add_to_archive(file_spec)
        for c in conf['commands']:
            if rm_conf and 'commands' in rm_conf and c['command'] in rm_conf['commands']:
                logger.warn("WARNING: Skipping command %s", c['command'])
                continue
            else:
                cmd_specs = self._parse_command_spec(c, conf['pre_commands'])
                for s in cmd_specs:
                    # spoof archive_file_name, will be reassembled in InsightsCommand()
                    s['archive_file_name'] = os.path.join('insights_commands', '_')
                    cmd_spec = InsightsCommand(s, exclude, self.mountpoint, self.target_name, self.config)
                    self.archive.add_to_archive(cmd_spec)
        logger.debug('Spec collection finished.')
        # collect metadata
        logger.debug('Collecting metadata...')
        self._write_branch_info(conf, branch_info)
        logger.debug('Metadata collection finished.')

    def run_collection(self, conf, rm_conf, branch_info):
        '''
        Run specs and collect all the data
        '''
        logger.debug('Beginning to run collection spec...')
        exclude = None
        if rm_conf:
            try:
                exclude = rm_conf['patterns']
            except LookupError:
                logger.debug('Could not parse remove.conf. Ignoring...')

        if 'specs' not in conf or InsightsClient.options.original_style_specs:
            # old style collection
            self._run_old_collection(conf, rm_conf, exclude, branch_info)
            return

        for specname in conf['specs']:
            try:
                # spec group for a symbolic name
                spec_group = conf['specs'][specname]
                # list of specs for a target
                # there might be more than one spec (for compatability)
                spec_list = spec_group[self.target_type]
                for spec in spec_list:
                    if 'file' in spec:
                        if rm_conf and 'files' in rm_conf and spec['file'] in rm_conf['files']:
                            logger.warn("WARNING: Skipping file %s", spec['file'])
                            continue
                        else:
                            file_specs = self._parse_file_spec(spec)
                            for s in file_specs:
                                file_spec = InsightsFile(s, exclude, self.mountpoint, self.target_name)
                                self.archive.add_to_archive(file_spec)
                    elif 'glob' in spec:
                        glob_specs = self._parse_glob_spec(spec)
                        for g in glob_specs:
                            if rm_conf and 'files' in rm_conf and g['file'] in rm_conf['files']:
                                logger.warn("WARNING: Skipping file %s", g)
                                continue
                            else:
                                glob_spec = InsightsFile(g, exclude, self.mountpoint, self.target_name)
                                self.archive.add_to_archive(glob_spec)
                    elif 'command' in spec:
                        if rm_conf and 'commands' in rm_conf and spec['command'] in rm_conf['commands']:
                            logger.warn("WARNING: Skipping command %s", spec['command'])
                            continue
                        else:
                            cmd_specs = self._parse_command_spec(spec, conf['pre_commands'])
                            for s in cmd_specs:
                                cmd_spec = InsightsCommand(s, exclude, self.mountpoint, self.target_name, self.config)
                                self.archive.add_to_archive(cmd_spec)
            except LookupError:
                logger.debug('Target type %s not found in spec %s. Skipping...', self.target_type, specname)
                continue
        logger.debug('Spec collection finished.')

        # collect metadata
        logger.debug('Collecting metadata...')
        self._write_analysis_target_type(conf)
        self._write_branch_info(conf, branch_info)
        self._write_analysis_target_id(conf)
        logger.debug('Metadata collection finished.')

    def done(self, conf, rm_conf):
        """
        Do finalization stuff
        """
        self._write_uploader_log(conf)
        if InsightsClient.config.getboolean(APP_NAME, "obfuscate"):
            cleaner = SOSCleaner(quiet=True)
            clean_opts = CleanOptions(self.archive.tmp_dir, rm_conf)
            fresh = cleaner.clean_report(clean_opts, self.archive.archive_dir)
            if clean_opts.keyword_file is not None:
                os.remove(clean_opts.keyword_file.name)
            return fresh[0]
        return self.archive.create_tar_file()


class CleanOptions(object):
    """
    Options for soscleaner
    """
    def __init__(self, tmp_dir, rm_conf):
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

        if InsightsClient.config.getboolean(APP_NAME, "obfuscate_hostname"):
            self.hostname_path = "insights_commands/hostname"
        else:
            self.hostname_path = None
