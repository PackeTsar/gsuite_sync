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
import argparse

# Built-In Libraries
import json
import logging


# log (console) is used to output data to the console properly formatted
log = logging.getLogger("console")
# datalog is used to output structured data without formatting
datalog = logging.getLogger("data")


def get_service(credfile):
    log.info("gsuite_sync.gsuite_pull.get_service:\
 Called. Pulling credential data from ({})".format(credfile))
    SCOPES = 'https://www.googleapis.com/auth/admin.directory.user'
    store = file.Storage(credfile)
    creds = store.get()
    log.info("gsuite_sync.gsuite_pull.get_service:\
 Pulled credentials. Connecting to GSuite")
    service = build('admin', 'directory_v1', http=creds.authorize(Http()))
    log.info("gsuite_sync.gsuite_pull.get_service:\
 Successfully connected to Google!")
    return service

def pull_devices(service):
    devices = []
    request = service.chromeosdevices().list(customerId='my_customer')
    response = request.execute()
#    log.debug("gsuite_sync.gsuite_pull.pull_devices:\
# Response:\n{}".format(json.dumps(response, indent=4)))
    devices += response["chromeosdevices"]
    log.info("gsuite_sync.gsuite_pull.pull_devices:\
 Inventoried ({}) devices so far".format(len(devices)))
    try:
        while "nextPageToken" in response:
            request = service.chromeosdevices().list_next(request, response)
            response = request.execute()
#            log.debug("gsuite_sync.gsuite_pull.pull_devices:\
# Response:\n{}".format(json.dumps(response, indent=4)))
            devices += response["chromeosdevices"]
            log.info("gsuite_sync.gsuite_pull.pull_devices:\
 Inventoried ({}) devices so far".format(len(devices)))
#        log.debug("gsuite_sync.gsuite_pull.pull_devices:\
#     All devices:\n{}".format(json.dumps(devices, indent=4)))
    except KeyboardInterrupt:
        log.warning("gsuite_sync.gsuite_pull.pull_devices:\
 Stopped, returning the ({}) devices we have so far".format(len(devices)))
    return devices


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
                        '-gc', "--gsuite_credential",
                        help="GSuite Credential File",
                        metavar='CRED_FILE',
                        dest="gsuite_credential")
    args = parser.parse_args()
    print(json.dumps(pull_devices(args.gsuite_credential), indent=4))
