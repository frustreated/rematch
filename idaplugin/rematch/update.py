# objects
from . import log
from . import config
from . import network
from . import exceptions
from . import utils
from .version import __version__

# builtin
import os
import shutil

try:
  import urllib2 as request
except ImportError:
  from urllib import request

import tempfile
import zipfile
from distutils.version import StrictVersion

# ida
import idc


class UpdateChecker(object):
  def __init__(self):
    self.q = None
    self.status = "pending"

  def check_update(self):
    if self.q:
      return

    if not config['settings']['update']['autocheck']:
      return

    url = "pypi/{package}/json".format(package=config['pypi']['package'])

    self.q = network.QueryWorker("GET", url, server=config['pypi']['server'],
                                 token="", json=True)
    self.q.start(self.handle_update, self.handle_exception)
    self.status = "pending"

  def handle_update(self, response):
    self.q = None

    local_version = StrictVersion(__version__)
    raw_remote_version = response['info']['version']
    remote_version = StrictVersion(raw_remote_version)
    log('update').info("local version: %s, latest version: %s", local_version,
                          remote_version)

    if remote_version < local_version:
      log('update').debug("You're using a version newer than latest")
      self.status = "ready"
      return
    if remote_version == local_version:
      log('update').debug("Version is up to date")
      self.status = "ready"
      return

    log('update').info("update is available")

    if str(remote_version) in config['settings']['update']['skipped']:
      log('update').info("version update marked skip")
      self.status = "skip"
      return

    if not config['settings']['update']['autoupdate']:
      update = idc.AskYN(1, "An update is available for the rematch IDA "
                            "plugin.\nVersion {} is available, while you're "
                            "using {}.\nWould you like to update your version?"
                            .format(remote_version, local_version))
      if update == 0:
        config['settings']['update']['skipped'].append(str(remote_version))
        log('update').info("Version update suppressed")
        self.status = "skip"
        return
      if update == -1:
        self.status = "skip"
        return

    # get latest version's package url
    new_release = response['releases'][raw_remote_version]
    new_url = new_release[0]['url']
    self.update_version(new_url)

  def update_version(self, url):
    package_path = '/idaplugin/'

    log('update').info("New version package url: %s", url)
    package_download = request.urlopen(url)
    temp_zip = tempfile.TemporaryFile()
    temp_dir = tempfile.mkdtemp()

    try:
      temp_zip.write(package_download.read())
      package_zip = zipfile.ZipFile(temp_zip)
      files = [f for f in package_zip.namelist() if package_path in f]
      package_zip.extractall(temp_dir, files)

      for filename in files:
        source = os.path.join(temp_dir, *filename.split('/'))
        target_file_parts = filename.split(package_path, 1)[1].split('/')
        target = utils.get_plugin_base(*target_file_parts)
        targetdir = os.path.dirname(target)
        if not os.path.exists(targetdir):
          os.makedirs(targetdir)
        shutil.move(source, target)
    finally:
      temp_zip.close()
      shutil.rmtree(temp_dir)

    self.status = "success"

  def handle_exception(self, exception, traceback):
    del traceback

    self.q = None
    self.status = "error"

    if isinstance(exception, exceptions.NotFoundException):
      log('update').info("Couldn't find latest release for plugin")
    else:
      log('update').error("Unknown error requesting update info",
                          exc_info=exception)
