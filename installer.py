#!/usr/bin/env python

import os

def install(alsi):
    alsi.install_pefile()

    # Install verify sigs
    pkg_file = "verify-sigs-master.zip"
    remote_path = os.path.join('pefile/' + pkg_file)
    local_path = os.path.join('/tmp/', pkg_file)

    alsi.fetch_package(remote_path, local_path)

    alsi.pip_install_all([local_path])

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
