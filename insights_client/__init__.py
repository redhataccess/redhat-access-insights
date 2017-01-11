#!/usr/bin/python
"""
 Gather and upload Insights data for
 Red Hat Insights
"""
import getpass
import json
import logging
import logging.handlers
import optparse
import os
import requests
import shutil
import sys
import time
import traceback
import atexit
from auto_config import try_auto_configuration
from utilities import (validate_remove_file,
                       generate_machine_id,
                       generate_analysis_target_id,
                       write_lastupload_file,
                       write_registered_file,
                       write_unregistered_file,
                       delete_registered_file,
                       delete_unregistered_file,
                       delete_machine_id,
                       determine_hostname,
                       modify_config_file)
from collection_rules import InsightsConfig
from data_collector import DataCollector
from schedule import InsightsSchedule
from connection import InsightsConnection
from archive import InsightsArchive
from support import InsightsSupport, registration_check
from constants import InsightsConstants as constants
from containers import (open_image,
                        open_container,
                        get_targets,
                        run_in_container,
                        insights_client_container_is_available,
                        docker_display_name,
                        container_image_links)
from client_config import InsightsClient, set_up_options, parse_config_file

__author__ = 'Jeremy Crafts <jcrafts@redhat.com>, Dan Varga <dvarga@redhat.com>'
LOG_FORMAT = ("%(asctime)s %(levelname)s %(message)s")
APP_NAME = constants.app_name
logger = logging.getLogger(__name__)


def set_up_logging():
    # TODO: come back to this
    """
    Initialize Logging
    """
    log_dir = constants.log_dir
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, 0700)
    logging_file = os.path.join(log_dir, APP_NAME + '.log')
    valid_levels = ['ERROR', 'DEBUG', 'INFO', 'WARNING', 'CRITICAL']
    handler = logging.handlers.RotatingFileHandler(logging_file,
                                                   backupCount=3)

    # from_stdin mode implies to_stdout
    InsightsClient.options.to_stdout = (InsightsClient.options.to_stdout or
                                        InsightsClient.options.from_stdin or
                                        InsightsClient.options.from_file)
    if InsightsClient.options.to_stdout and not InsightsClient.options.verbose:
        InsightsClient.options.quiet = True

    # Send anything INFO+ to stdout and log
    stdout_handler = logging.StreamHandler(sys.stdout)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.ERROR)
    logging.root.addHandler(stderr_handler)
    if not InsightsClient.options.verbose:
        stdout_handler.setLevel(logging.INFO)
    if InsightsClient.options.quiet:
        stdout_handler.setLevel(logging.ERROR)
    if not InsightsClient.options.silent:
        logging.root.addHandler(stdout_handler)

    logging.root.addHandler(handler)

    formatter = logging.Formatter(LOG_FORMAT)
    handler.setFormatter(formatter)
    logging.root.setLevel(logging.WARNING)
    if InsightsClient.options.verbose:
        config_level = 'DEBUG'
    else:
        config_level = InsightsClient.config.get(APP_NAME, 'loglevel')

    if config_level in valid_levels:
        init_log_level = logging.getLevelName(config_level)
    else:
        print "Invalid log level %s, defaulting to DEBUG" % config_level
        init_log_level = logging.getLevelName("DEBUG")

    logger.setLevel(init_log_level)
    logging.root.setLevel(init_log_level)
    logger.debug("Logging initialized")
    return handler


def handle_startup():
    """
    Handle startup options
    """
    # ----do X and exit options----
    # show version and exit
    if InsightsClient.options.version:
        print constants.version
        sys.exit()

    if (InsightsClient.options.container_mode and
            not InsightsClient.options.run_here and
            insights_client_container_is_available()):
        sys.exit(run_in_container())

    if InsightsClient.options.validate:
        validate_remove_file()
        sys.exit()

    if InsightsClient.options.enable_schedule and InsightsClient.options.disable_schedule:
        logger.error('Conflicting options: --enable-schedule and --disable-schedule')
        sys.exit(1)

    if InsightsClient.options.enable_schedule:
        # enable automatic scheduling
        InsightsSchedule()
        InsightsClient.config.set(APP_NAME, 'no_schedule', False)
        logger.info('Automatic scheduling for Insights has been enabled.')
        logger.debug('Updating config...')
        modify_config_file({'no_schedule': 'False'})
        sys.exit()

    if InsightsClient.options.disable_schedule:
        # disable automatic schedling
        InsightsSchedule(set_cron=False).remove_scheduling()
        InsightsClient.config.set(APP_NAME, 'no_schedule', True)
        logger.info('Automatic scheduling for Insights has been disabled.')
        logger.debug('Updating config...')
        modify_config_file({'no_schedule': 'True'})
        sys.exit()

    # do auto_config here, for connection-related 'do X and exit' options
    if InsightsClient.config.getboolean(APP_NAME, 'auto_config') and not InsightsClient.options.offline:
        # Try to discover if we are connected to a satellite or not
        try_auto_configuration()

    if InsightsClient.options.test_connection:
        pconn = InsightsConnection()
        rc = pconn.test_connection()
        sys.exit(rc)

    if InsightsClient.options.status:
        reg_check = registration_check()
        logger.info('\n'.join(reg_check['messages']))
        # exit with !status, 0 for True, 1 for False
        sys.exit(not reg_check['status'])

    if InsightsClient.options.support:
        support = InsightsSupport()
        support.collect_support_info()
        sys.exit()

    # ----config options----
    # log the config
    # ignore password and proxy -- proxy might have pw
    for item, value in InsightsClient.config.items(APP_NAME):
        if item != 'password' and item != 'proxy':
            logger.debug("%s:%s", item, value)

    if InsightsClient.config.getboolean(APP_NAME, 'auto_update') and not InsightsClient.options.offline:
        # TODO: config updates option, but in GPG option, the option updates
        # the config.  make this consistent
        InsightsClient.options.update = True

    # disable automatic scheduling if it was set in the config, and if the job exists
    if InsightsClient.config.getboolean(APP_NAME, 'no_schedule'):
        cron = InsightsSchedule(set_cron=False)
        if cron.already_linked():
            cron.remove_scheduling()
            logger.debug('Automatic scheduling for Insights has been disabled.')

    # ----modifier options----
    if InsightsClient.options.no_gpg:
        logger.warn("WARNING: GPG VERIFICATION DISABLED")
        InsightsClient.config.set(APP_NAME, 'gpg', 'False')

    if InsightsClient.options.just_upload:
        if InsightsClient.options.offline or InsightsClient.options.no_upload:
            logger.error('Cannot use --just-upload in combination with --offline or --no-upload.')
            sys.exit(1)
        # override these for great justice
        InsightsClient.options.no_tar_file = False
        InsightsClient.options.keep_archive = True

    if InsightsClient.options.container_mode and InsightsClient.options.no_tar_file:
        logger.error('Invalid combination: --container and --no-tar-file')
        sys.exit(1)

    # can't use bofa
    if InsightsClient.options.from_stdin and InsightsClient.options.from_file:
        logger.error('Can\'t use both --from-stdin and --from-file.')
        sys.exit(1)

    if InsightsClient.options.to_stdout:
        InsightsClient.options.no_upload = True

    # ----register options----
    # put this first to avoid conflicts with register
    if InsightsClient.options.unregister:
        pconn = InsightsConnection()
        pconn.unregister()
        sys.exit()

    # force-reregister -- remove machine-id files and registration files
    # before trying to register again
    new = False
    if InsightsClient.options.reregister:
        new = True
        InsightsClient.options.register = True
        delete_registered_file()
        delete_unregistered_file()
        delete_machine_id()
    logger.debug('Machine-id: %s', generate_machine_id(new))

    if InsightsClient.options.register:
        try_register()
        if not InsightsClient.config.getboolean(APP_NAME, 'no_schedule'):
            InsightsSchedule()

    # check registration before doing any uploads
    # Ignore if in offline mode
    if not InsightsClient.options.register and not InsightsClient.options.offline:
        msg, is_registered = _is_client_registered()
        if not is_registered:
            logger.error(msg)
            sys.exit(1)


def _is_client_registered():
    msg_notyet = 'This machine has not yet been registered.'
    msg_unreg = 'This machine has been unregistered.'
    msg_doreg = 'Use --register to register this machine.'
    msg_rereg = 'Use --register if you would like to re-register this machine.'
    msg_exit = 'Exiting...'
    # check reg status w/ API
    reg_check = registration_check()
    if not reg_check['status']:
        # not registered
        if reg_check['unreg_date']:
            # system has been unregistered from the UI
            msg = '\n'.join([msg_unreg, msg_rereg, msg_exit])
            write_unregistered_file(reg_check['unreg_date'])
            return msg, False
        else:
            # no record of system in remote
            msg = '\n'.join([msg_notyet, msg_doreg, msg_exit])
            # clear any local records
            delete_registered_file()
            delete_unregistered_file()
            return msg, False
    else:
        # API confirms reg
        if not os.path.isfile(constants.registered_file):
            write_registered_file()
        # delete any stray unregistered
        delete_unregistered_file()
        return '', True


def handle_branch_info_error(msg):
    if InsightsClient.options.offline or InsightsClient.options.no_upload:
        logger.warning(msg)
        logger.warning("Assuming remote branch and leaf value of -1")
        return constants.default_branch_info
    else:
        logger.error("ERROR: %s", msg)
        sys.exit(1)


def handle_exception(exc_type, exc_value, exc_traceback):
    """
    Exception handler so exception messages land in our log instead of them
    vanishing into thin air, or abrt picking them up
    """
    if issubclass(exc_type, KeyboardInterrupt):
        sys.exit(1)
    if logger:
        logger.error(
            traceback.format_exception(exc_type, exc_value, exc_traceback))
    else:
        print traceback.format_exception(exc_type, exc_value, exc_traceback)
        sys.exit('Caught unhandled exception, check log for more information')


def trace_calls(frame, event, arg):
    if event != 'call':
        return
    co = frame.f_code
    func_name = co.co_name
    if func_name == 'write':
        return
    func_line_no = frame.f_lineno
    func_filename = co.co_filename
    caller = frame.f_back
    caller_line_no = caller.f_lineno
    caller_filename = caller.f_code.co_filename
    print 'Call to %s on line %s of %s from line %s of %s' % \
        (func_name, func_line_no, func_filename,
         caller_line_no, caller_filename)
    return


def try_register():
    if os.path.isfile(constants.registered_file):
        logger.info('This host has already been registered.')
        return
    # check reg status with API
    reg_check = registration_check()
    if reg_check['status']:
        logger.info('This host has already been registered.')
        # regenerate the .registered file
        write_registered_file()
        return
    message, hostname, group, display_name = register()
    if InsightsClient.options.display_name is None and InsightsClient.options.group is None:
        logger.info('Successfully registered %s', hostname)
    elif InsightsClient.options.display_name is None:
        logger.info('Successfully registered %s in group %s', hostname, group)
    else:
        logger.info('Successfully registered %s as %s in group %s',
                    hostname, display_name, group)
    if message:
        logger.info(message)


def register():
    """
    Do registration using basic auth
    """
    username = InsightsClient.config.get(APP_NAME, 'username')
    password = InsightsClient.config.get(APP_NAME, 'password')
    authmethod = InsightsClient.config.get(APP_NAME, 'authmethod')
    # TODO validate this is boolean somewhere in config load
    auto_config = InsightsClient.config.getboolean(APP_NAME, 'auto_config')
    if not username and not password and not auto_config and authmethod == 'BASIC':
        print 'Please enter your Red Hat Customer Portal Credentials'
        sys.stdout.write('Username: ')
        username = raw_input().strip()
        password = getpass.getpass()
        sys.stdout.write('Would you like to save these credentials? (y/n) ')
        save = raw_input().strip()
        InsightsClient.config.set(APP_NAME, 'username', username)
        InsightsClient.config.set(APP_NAME, 'password', password)
        logger.debug('savestr: %s', save)
        if save.lower() == 'y' or save.lower() == 'yes':
            logger.debug('Writing user/pass to config')
            modify_config_file({'username': username, 'password': password})
    pconn = InsightsConnection()
    return pconn.register()


def _delete_archive(archive):
    # delete archive on unexpected exit
    if not (InsightsClient.options.keep_archive or
            InsightsClient.options.offline or
            InsightsClient.options.no_upload or
            InsightsClient.options.no_tar_file or
            InsightsClient.config.getboolean(APP_NAME, "obfuscate")):
        archive.delete_tmp_dir()


def _create_metadata_json(archives):
    metadata = {'display_name': archives[-1]['display_name'],
                'product': 'Docker',
                'system_id': generate_machine_id(docker_group=True),
                'systems': []}

    # host archive is appended to the end of the targets array,
    #   so it will always be the last one (index -1)
    docker_links = []
    c_i_links = container_image_links()
    for a in archives:
        system = {}
        if a['type'] == 'host':
            system['links'] = docker_links
        else:
            docker_links.append({
                'system_id': a['system_id'],
                'type': a['type']
            })
            system['links'] = [{'system_id': archives[-1]['system_id'],
                                'type': 'host'}]
            if a['docker_id'] in c_i_links:
                system['links'].extend(c_i_links[a['docker_id']])
            system['docker_id'] = a['docker_id']
        system['display_name'] = a['display_name']
        system['product'] = a['product']
        system['system_id'] = a['system_id']
        system['type'] = a['type']
        metadata['systems'].append(system)
    return metadata


def collect_data_and_upload(rc=0):
    """
    All the heavy lifting done here
    Run through "targets" - could be just one (host, default) or many (containers+host)
    """
    # initialize collection targets
    # for now we do either containers OR host -- not both at same time
    if InsightsClient.options.container_mode:
        targets = get_targets()
        targets = targets + constants.default_target
    else:
        targets = constants.default_target

    if InsightsClient.options.offline:
        logger.warning("Assuming remote branch and leaf value of -1")
        pconn = None
        branch_info = constants.default_branch_info
    else:
        pconn = InsightsConnection()

    # TODO: change these err msgs to be more meaningful , i.e.
    # "could not determine login information"
    if pconn:
        try:
            branch_info = pconn.branch_info()
        except requests.ConnectionError:
            branch_info = handle_branch_info_error(
                "Could not connect to determine branch information")
        except LookupError:
            branch_info = handle_branch_info_error(
                "Could not determine branch information")
    pc = InsightsConfig(pconn)

    if InsightsClient.options.just_upload:
        if not os.path.exists(InsightsClient.options.just_upload):
            logger.error('No file %s', InsightsClient.options.just_upload)
            return 1
        tar_file = InsightsClient.options.just_upload
        rc = _do_upload(pconn, tar_file, 'dummy', 0)
        return rc

    # load config from stdin/file if specified
    try:
        stdin_config = {}
        if InsightsClient.options.from_file:
            with open(InsightsClient.options.from_file, 'r') as f:
                stdin_config = json.load(f)
        elif InsightsClient.options.from_stdin:
            stdin_config = json.load(sys.stdin)
        if ((InsightsClient.options.from_file or InsightsClient.options.from_stdin) and
            ('uploader.json' not in stdin_config or
             'sig' not in stdin_config)):
            raise ValueError
        if ((InsightsClient.options.from_file or InsightsClient.options.from_stdin) and
                'branch_info' in stdin_config and stdin_config['branch_info'] is not None):
            branch_info = stdin_config['branch_info']
    except:
        logger.error('ERROR: Invalid config for %s! Exiting...',
                     ('--from-file' if InsightsClient.options.from_file else '--from-stdin'))
        sys.exit(1)

    start = time.clock()
    collection_rules, rm_conf = pc.get_conf(InsightsClient.options.update, stdin_config)
    collection_elapsed = (time.clock() - start)
    logger.debug("Rules configuration loaded. Elapsed time: %s", collection_elapsed)

    individual_archives = []

    for t in targets:
        # defaults
        archive = None
        container_connection = None
        mp = None
        obfuscate = None
        # archive metadata
        archive_meta = {}

        try:
            if t['type'] == 'docker_image':
                container_connection = open_image(t['name'])
                logging_name = 'Docker image ' + t['name']
                archive_meta['docker_id'] = t['name']
                archive_meta['display_name'] = docker_display_name(
                    t['name'], t['type'].replace('docker_', ''))
                logger.debug('Docker display_name: %s', archive_meta['display_name'])
                logger.debug('Docker docker_id: %s', archive_meta['docker_id'])
                if container_connection:
                    mp = container_connection.get_fs()
                else:
                    logger.error('Could not open %s for analysis', logging_name)
                    continue
            elif t['type'] == 'docker_container':
                container_connection = open_container(t['name'])
                logging_name = 'Docker container ' + t['name']
                archive_meta['docker_id'] = t['name']
                archive_meta['display_name'] = docker_display_name(
                    t['name'], t['type'].replace('docker_', ''))
                logger.debug('Docker display_name: %s', archive_meta['display_name'])
                logger.debug('Docker docker_id: %s', archive_meta['docker_id'])
                if container_connection:
                    mp = container_connection.get_fs()
                else:
                    logger.error('Could not open %s for analysis', logging_name)
                    continue
            elif t['type'] == 'host':
                logging_name = determine_hostname()
                archive_meta['display_name'] = determine_hostname(
                    InsightsClient.options.display_name)
            else:
                logger.error('Unexpected analysis target: %s', t['type'])
                continue

            archive_meta['type'] = t['type'].replace('docker_', '')
            archive_meta['product'] = 'Docker'
            archive_meta['system_id'] = generate_analysis_target_id(t['type'], t['name'])

            collection_start = time.clock()
            archive = InsightsArchive(compressor=InsightsClient.options.compressor if not InsightsClient.options.container_mode else "none",
                                      target_name=t['name'])
            atexit.register(_delete_archive, archive)
            dc = DataCollector(archive,
                               InsightsClient.config,
                               mountpoint=mp,
                               target_name=t['name'],
                               target_type=t['type'])

            logger.info('Starting to collect Insights data for %s', logging_name)
            dc.run_collection(collection_rules, rm_conf, branch_info)
            elapsed = (time.clock() - start)
            logger.debug("Data collection complete. Elapsed time: %s", elapsed)

            obfuscate = InsightsClient.config.getboolean(APP_NAME, "obfuscate")

            # include rule refresh time in the duration
            collection_duration = (time.clock() - collection_start) + collection_elapsed

            if InsightsClient.options.no_tar_file:
                logger.info('See Insights data in %s', dc.archive.archive_dir)
                return rc

            tar_file = dc.done(collection_rules, rm_conf)

            # add archives to list of individual uploads
            archive_meta['tar_file'] = tar_file
            individual_archives.append(archive_meta)

        finally:
            # called on loop iter end or unexpected exit
            if container_connection:
                container_connection.close()

    # if multiple targets (container mode), add all archives to single archive
    if InsightsClient.options.container_mode:
        full_archive = InsightsArchive(compressor=InsightsClient.options.compressor)
        for a in individual_archives:
            shutil.copy(a['tar_file'], full_archive.archive_dir)
        # don't want insights_commands in meta archive
        shutil.rmtree(full_archive.cmd_dir)
        metadata = _create_metadata_json(individual_archives)
        full_archive.add_metadata_to_archive(json.dumps(metadata), 'metadata.json')
        full_tar_file = full_archive.create_tar_file(full_archive=True)
    # if only one target (regular mode), just upload one
    else:
        full_archive = archive
        full_tar_file = tar_file

    if InsightsClient.options.offline or InsightsClient.options.no_upload:
        handle_file_output(full_tar_file, full_archive)
        return rc

    # do the upload
    rc = _do_upload(pconn, full_tar_file, logging_name, collection_duration)

    if InsightsClient.options.keep_archive:
        logger.info('Insights data retained in %s', full_tar_file)
        return rc
    if obfuscate:
        logger.info('Obfuscated Insights data retained in %s',
                    os.path.dirname(full_tar_file))
    full_archive.delete_archive_dir()
    return rc


def _do_upload(pconn, tar_file, logging_name, collection_duration, rc=0):
    # do the upload
    logger.info('Uploading Insights data for %s, this may take a few minutes', logging_name)
    for tries in range(InsightsClient.options.retries):
        upload = pconn.upload_archive(tar_file, collection_duration,
                                      cluster=generate_machine_id(
                                          docker_group=InsightsClient.options.container_mode))
        if upload.status_code == 201:
            write_lastupload_file()
            logger.info("Upload completed successfully!")
            break
        elif upload.status_code == 412:
            pconn.handle_fail_rcs(upload)
        else:
            logger.error("Upload attempt %d of %d failed! Status Code: %s",
                         tries + 1, InsightsClient.options.retries, upload.status_code)
            if tries + 1 != InsightsClient.options.retries:
                logger.info("Waiting %d seconds then retrying",
                            constants.sleep_time)
                time.sleep(constants.sleep_time)
            else:
                logger.error("All attempts to upload have failed!")
                logger.error("Please see %s for additional information",
                             constants.default_log_file)
                rc = 1
    return rc


def handle_file_output(tar_file, archive):
    if InsightsClient.options.to_stdout:
        shutil.copyfileobj(open(tar_file, 'rb'), sys.stdout)
        archive.delete_tmp_dir()
    else:
        logger.info('See Insights data in %s', tar_file)


def _main():
    """
    Main entry point
    Parse cmdline options
    Parse config file
    Call data collector
    """
    if os.geteuid() is not 0:
        sys.exit("Red Hat Insights must be run as root")

    sys.excepthook = handle_exception

    parser = optparse.OptionParser()
    set_up_options(parser)
    options, args = parser.parse_args()
    if len(args) > 0:
        parser.error("Unknown arguments: %s" % args)
        sys.exit(1)
    config = parse_config_file(options.conf)

    # copy to global config object
    InsightsClient.config = config
    InsightsClient.options = options
    InsightsClient.argv = sys.argv
    handler = set_up_logging()

    if InsightsClient.config.getboolean(APP_NAME, 'trace'):
        sys.settrace(trace_calls)

    # Defer logging till it's ready
    logger.debug('invoked with args: %s', InsightsClient.options)
    logger.debug("Version: " + constants.version)

    # Handle all the options
    handle_startup()

    # Vaccuum up the data
    rc = collect_data_and_upload()

    # Roll log over on successful upload
    if not rc:
        handler.doRollover()
    sys.exit(rc)

if __name__ == '__main__':
    _main()
