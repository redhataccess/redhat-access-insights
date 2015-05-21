"""
Module responsible for scheduling Insights data collection
"""
import os
import logging
from constants import InsightsConstants as constants

CRON_DAILY = '/etc/cron.daily/'
CRON_WEEKLY = '/etc/cron.weekly/'
APP_NAME = constants.app_name
logger = logging.getLogger(APP_NAME)


class InsightsSchedule(object):
    """
    Set the cron schedule
    """
    def __init__(self, options):
        if not self.already_linked():
            self.set_daily()
        if options.daily:
            self.set_daily()
            logger.info("Set schedule to daily")
        if options.weekly:
            self.set_weekly()
            logger.info("Set schedule to weekly")

    def already_linked(self):
        """
        Determine if we are already scheduled
        """
        if os.path.isfile(CRON_WEEKLY + APP_NAME):
            logger.debug('Found cron.weekly')
            return True
        elif os.path.isfile(CRON_DAILY + APP_NAME):
            logger.debug('Found cron.daily')
            return True
        else:
            return False

    def set_daily(self):
        """
        Set cron task to daily
        """
        logger.debug('Setting schedule to daily')
        try:
            os.remove(CRON_WEEKLY + APP_NAME)
        except OSError:
            logger.debug('Could not remove cron.weekly')

        try:
            os.symlink(
                '/etc/' + APP_NAME + '/' + APP_NAME + '.cron',
                CRON_DAILY + APP_NAME)
        except OSError:
            logger.debug('Could not link cron.daily')

    def set_weekly(self):
        """
        Set cron task to weekly
        """
        logger.debug('Setting schedule to weekly')
        try:
            os.remove(CRON_DAILY + APP_NAME)
        except OSError:
            logger.debug('Could not remove cron.daily')

        try:
            os.symlink(
                '/etc/' + APP_NAME + '/' + APP_NAME + '.cron',
                CRON_WEEKLY + APP_NAME)
        except OSError:
            logger.debug('Could not link cron.weekly')
