import pytest
import subprocess, logging
import os, sys, re, fileinput
from subprocess import Popen, PIPE

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s %(message)s')
mylogger = logging.getLogger()

def test_option_daily_check():
	subprocess.call(['redhat-access-insights --schedule --daily'], shell=True)
	if os.path.isfile("/etc/cron.daily/redhat-access-insights"):
		mylogger.debug("cron job set to daily - VERIFIED")
	else:
		pytest.fail("Cron job not set to daily")

def test_option_weekly_check():
	subprocess.call(['redhat-access-insights --schedule --weekly'], shell=True)
	if os.path.isfile("/etc/cron.weekly/redhat-access-insights"):
		mylogger.debug("Cron job set to weekly - VERIFIED")
		pass
	else:
		pytest.fail("Cron job not set to weekly")

def test_gpg_verification_check():
	check_gpg = subprocess.Popen(["redhat-access-insights"], stdout=subprocess.PIPE, shell=True)
	gpg_check_text, err = check_gpg.communicate()
	var = re.compile(r".*Upload completed successfully.*")
	if re.search(var, gpg_check_text) is not None:
		pass
		mylogger.debug("GPG verification - VERIFIED")
	else:
		print gpg_check_text, err
		pytest.fail("GPG verification not done")

	try:
		mylogger.debug("checking if the gpg check fails on modifying .cache.json")
		os.system("cp /etc/redhat-access-insights/.cache.json /etc/redhat-access-insights/.cache.json.backup")
		with open("/etc/redhat-access-insights/.cache.json", "a") as f:
			f.write("#changing .cache.json")

		os.system("cp /etc/redhat-access-insights/redhat-access-insights.conf /etc/redhat-access-insights/redhat-access-insights.conf.backup")
		with open("/etc/redhat-access-insights/redhat-access-insights.conf", "r") as f:
			auto_update_change = f.read().replace("#auto_update=True","auto_update=False")
		with open("/etc/redhat-access-insights/redhat-access-insights.conf", "w") as f:
			f.write(auto_update_change)

		gpg = subprocess.Popen(["redhat-access-insights"], stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
		gpg_output, gpg_err = gpg.communicate()
		gpg_regex = re.compile(r".*Unable to validate gpg signature.*")
		print "Console output:"
		print gpg_err
		if re.search(gpg_regex, gpg_err) is not None:
			pass
			print "Upload must fail if gpg signature not verified - VERIFIED"
		else:
			pytest.fail("should not be able to upload successfully without gpg verification")

	except Exception as e:
		print e
		os.system("rm /etc/redhat-access-insights/.cache.json")
		os.system("mv /etc/redhat-access-insights/.cache.json.backup /etc/redhat-access-insights/.cache.json")
		os.system("rm /etc/redhat-access-insights/redhat-access-insights.conf")
		os.system("mv /etc/redhat-access-insights/redhat-access-insights.conf.backup /etc/redhat-access-insights/redhat-access-insights.conf")
		print "reverted changes made to .cache.json and redhat-access-insights.conf"
		pytest.fail("should not be able to upload successfully without gpg verification")

	os.system("rm /etc/redhat-access-insights/.cache.json")
	os.system("mv /etc/redhat-access-insights/.cache.json.backup /etc/redhat-access-insights/.cache.json")
	print "Reverting changes made to /etc/redhat-access-insights/.cache.json and /etc/redhat-access-insights/redhat-access-insights.conf"
	os.system("rm /etc/redhat-access-insights/redhat-access-insights.conf")
	os.system("mv /etc/redhat-access-insights/redhat-access-insights.conf.backup /etc/redhat-access-insights/redhat-access-insights.conf")

def test_gpg_verification_disabled_check():
	gpg_disabled = subprocess.Popen(["redhat-access-insights --no-gpg"], stdout=subprocess.PIPE, shell=True)
	gpg_check_text, err = gpg_disabled.communicate()
	if re.search("GPG VERIFICATION DISABLED", gpg_check_text) is not None:
		pass
		mylogger.debug("--no-gpg option disables gpg verification successfully")
	else:
		pytest.fail("--no-gpg was not able to disable gpg verification")

def test_blacklist_functionality_with_keep_archive():
	if os.path.isfile("/etc/redhat-access-insights/remove.json"):
		os.system("rm /etc/redhat-access-insights/remove.json")
	os.system("cp ./tests/data/remove.json /etc/redhat-access-insights/")
	if os.path.isfile("/etc/redhat-access-insights/remove.json"):
		remove_json = subprocess.Popen(["redhat-access-insights --keep-archive"], stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
		output, err = remove_json.communicate()
		print output
		archive_regex = re.compile(r"Insights data retained in /var/tmp/.*")
		archive_dir = re.search(archive_regex, output)
		dir_archived = archive_dir.group(0).split("in ")[1]
		archive_name =  dir_archived.split("/")[-1]
		print archive_name
		os.system("tar -xf %s -C /tmp" % dir_archived)
		archive_directory = archive_name.split(".tar")[0]

		if os.path.isfile("/tmp/%s/insights_commands/lspci" %archive_directory):
			pytest.fail("The command '/sbin/lspci' in the remove.json did not get blacklisted")
		else:
			print "The command '/sbin/lspci' from remove.json got blacklisted(not executed) - VERIFIED"
		print "Files in the archived dir:"
		print os.system("cd /tmp/%s/etc;ls" % archive_directory)
		if os.path.isfile("/tmp/%s/etc/hosts" %archive_directory ):
			pytest.fail("The file 'etc/ssh/hosts' from remove.json did not get blacklisted")
		else:
			print "The file 'etc/hosts from remove.json got blacklisted - VERIFIED"
		os.system("rm -rf /tmp/%s" %archive_directory)
		print "deleting archived dir in /tmp/%s" %archive_directory

def test_machine_id_verification():
	if os.path.isfile("/etc/redhat-access-insights/machine-id"):
		machine_id = subprocess.Popen(["cat /etc/redhat-access-insights/machine-id"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		machineid, err = machine_id.communicate()
		print "\n'/etc/redhat-access-insights/machine-id' is present as: %s" %machineid
	else:
		pytest.fail("'/etc/redhat-access-insights/machine-id' is not present")
		print err

def test_no_upload_option():
	no_upload = subprocess.Popen(["redhat-access-insights --no-upload"], stdout=subprocess.PIPE, shell=True)
	no_upload_output, err = no_upload.communicate()
	print no_upload_output
	tar_regex = re.compile(r".*tar\.gz.*")
	if re.search(tar_regex, no_upload_output) is not None and re.search("Upload completed successully!", no_upload_output) is None:
		tar_file = no_upload_output.split("See Insights data in ")[1]
		print tar_file
	else:
		print err
		pytest.fail("The upload was successfull despite of the option --no-upload")

	os.system("rm -rf  /var/tmp/%s" % tar_file.split("/")[3])
	print "Deleted tar file %s" %tar_file

def test_no_tar_file_option():
	no_tar_file = subprocess.Popen(["redhat-access-insights --no-tar-file"], stdout=subprocess.PIPE, shell=True)
	no_tar_output, err = no_tar_file.communicate()
	print no_tar_output
	tar_regex = re.compile(r".*tar\.gz.*")
	if re.search(tar_regex, no_tar_output) is None and re.search("Upload completed successully!", no_tar_output) is None:
		no_tar_dir = no_tar_output.split("See Insights data in ")[1]
		print no_tar_dir
	else:
		print err
		pytest.fail("The tar file should not have been created with usage of option --no-tar-file")

	os.system("rm -rf  /var/tmp/%s" % no_tar_dir.split("/")[3])
	print "Deleted tar file %s" %no_tar_dir

