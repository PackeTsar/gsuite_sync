#!/usr/bin/python

"""
gsuite_sync.gsuite_pull contains the functions used to pull Chrome device data
from a GSuite account.
"""


# Installed Libraries
from __future__ import print_function
from apiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools
from builtins import input

# Built-In Libraries
import json
import logging


# log (console) is used to output data to the console properly formatted
log = logging.getLogger("console")
# datalog is used to output structured data without formatting
datalog = logging.getLogger("data")


def pull_devices(credfile):
    log.info("gsuite_sync.gsuite_pull.pull_devices:\
 Called. Pulling credential data from ({})".format(credfile))
    SCOPES = 'https://www.googleapis.com/auth/admin.directory.user'
    store = file.Storage(credfile)
    creds = store.get()
    log.info("gsuite_sync.gsuite_pull.pull_devices:\
 Successfully pulled credentials. Connecting to GSuite")
    service = build('admin', 'directory_v1', http=creds.authorize(Http()))
    log.info("gsuite_sync.gsuite_pull.pull_devices:\
 Connection successful. Pulling device list...")
    devices = service.chromeosdevices().list(
        customerId='my_customer').execute()
    log.info("gsuite_sync.gsuite_pull.pull_devices:\
 Successfully pulled devices from GSuite")
    log.debug("gsuite_sync.gsuite_pull.pull_devices:\
 Device data:\n{}".format(json.dumps(devices, indent=4)))
    return devices


if __name__ == "__main__":
    credfile = input("Credentials File Path: ")
    print(json.dumps(pull_devices(credfile), indent=4))
