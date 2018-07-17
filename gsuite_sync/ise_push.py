#!/usr/bin/python

"""
"""


# Installed Libraries
from __future__ import print_function
from builtins import input
import requests
import urllib3


# Built-In Libraries
import json
import logging
from base64 import b64encode
import getpass


# log (console) is used to output data to the console properly formatted
log = logging.getLogger("console")
# datalog is used to output structured data without formatting
datalog = logging.getLogger("data")
# Disable SSL warnings
urllib3.disable_warnings()


def pull_macs(address, username, password):
    url = "https://{}:9060/ers/config/internaluser/versioninfo".format(address)
    authcode = b64encode(b"{}:{}".format(username, password))
    authcode = authcode.decode("ascii")
    authstring = "Basic {}".format(authcode)
    headers = {
        "accept": "application/json",
        "authorization": authstring,
        "cache-control": "no-cache"
    }
    response = requests.request("GET", url, headers=headers, verify=False)
    return json.loads(response.text)


if __name__ == "__main__":
    address = input("Address: ")
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    print(json.dumps(pull_macs(address, username, password), indent=4))
