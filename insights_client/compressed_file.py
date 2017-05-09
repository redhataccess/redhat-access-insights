"""
Handle compressed filesystems
This replicates functionality that 'archivemount' would provide
"""
import logging
import tempfile
import tarfile
import os
from constants import InsightsConstants as constants

logger = logging.getLogger(constants.app_name)


class InsightsCompressedFile(object):

    """
    This class handles uncompressing and mounting compressed filesystems
    """

    def __init__(self, compressed_file_location=None):
        self.compressed_file_location = compressed_file_location
        self.tmp_dir = tempfile.mkdtemp(prefix='/var/tmp/')
        self.is_file = os.path.isfile(self.compressed_file_location)
        self.is_tarfile = tarfile.is_tarfile(self.compressed_file_location) if self.is_file else False
        if self.is_file and self.is_tarfile:
            try:
                tar = tarfile.open(self.compressed_file_location)
                tar.extractall(path=self.tmp_dir)
                tar.close()
            except:
                logger.debug("Invalid compressed tar filesystem provided. Could not extract contents.")
        else:
            logger.debug("Invalid compressed tar filesystem provided.")

    def cleanup_temp_filesystem(self):
        """
        Cleanup the temporary directory
        """
        logger.debug("Deleting compressed file extraction directory: " + self.tmp_dir)
        shutil.rmtree(self.tmp_dir, True)

    def get_filesystem_path(self):
        """
        Get the filesystem path, where it was extracted to
        """
        return self.tmp_dir