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
import argparse
import time
import os


# log (console) is used to output data to the console properly formatted
log = logging.getLogger("console")
# bulklog is used to output structured data without formatting
bulklog = logging.getLogger("bulk")
# Disable SSL warnings
urllib3.disable_warnings()


class ise_auth:
    def __init__(self, address, username, password):
        self.address = address
        self.username = username
        self.password = password
        self.good_codes = [200, 201, 202, 204]
        self.authstring = self._gen_authstring()
        self.session = requests.Session()
        self.headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "authorization": self.authstring,
            "cache-control": "no-cache"
        }
        log.debug("gsuite_sync.ise.ise_auth.__init__:\
 Instantiated ISE authentication with headers:\n{}".format(
                 json.dumps(self.headers, indent=4)))
        self.ise_version = self.get("/ers/config/internaluser/versioninfo")
        log.info("gsuite_sync.ise.ise_auth.__init__:\
 Successfully connected to ISE!")
        log.debug("gsuite_sync.ise.ise_auth.__init__:\
 ISE Version Info:\n{}".format(
                 self.ise_version.text))

    def _gen_authstring(self):
        authcode = b64encode(b"{}:{}".format(self.username, self.password))
        authcode = authcode.decode("ascii")
        authstring = "Basic {}".format(authcode)
        return authstring

    def get(self, uri):
        url = "https://{}:9060{}".format(self.address, uri)
        response = self.session.get(
            url,
            headers=self.headers,
            verify=False)
        if response.status_code not in self.good_codes:
            raise Exception("Bad ISE Response ({}):\n{}\n{}".format(
                response.status_code,
                json.dumps(dict(response.headers), indent=4),
                response.text))
        bulklog.info("gsuite_sync.ise.ise_auth.get:\
 Response:\nCode: {}\nHeaders: {}\nBody: {}".format(
            response,
            json.dumps(dict(response.headers), indent=4),
            response.text))
        return response

    def put(self, uri, data):
        url = "https://{}:9060{}".format(self.address, uri)
        response = self.session.put(
            url,
            data=data,
            headers=self.headers,
            verify=False)
        if response.status_code not in self.good_codes:
            raise Exception("Bad ISE Response ({}):\n{}".format(
                str(response.status_code),
                response.text))
        bulklog.info("gsuite_sync.ise.ise_auth.put:\
 Response:\nCode: {}\nHeaders: {}\nBody: {}".format(
            response,
            json.dumps(dict(response.headers), indent=4),
            response.text))
        return response

    def post(self, uri, data):
        url = "https://{}:9060{}".format(self.address, uri)
        response = self.session.post(
            url,
            data=data,
            headers=self.headers,
            verify=False)
        if response.status_code not in self.good_codes:
            raise Exception("Bad ISE Response ({}):\n{}".format(
                str(response.status_code),
                response.text))
        bulklog.info("gsuite_sync.ise.ise_auth.post:\
 Response:\nCode: {}\nHeaders: {}\nBody: {}".format(
            response,
            json.dumps(dict(response.headers), indent=4),
            response.text))
        return response


def pull_endpoint_list(address, username, password, group_name):
    group = pull_group(address, username, password, group_name)
    id = group["id"]
    url = "https://{}:9060/ers/config/endpoint?filter=groupId.EQ.{}".format(
        address, id)
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


def create_mac(address, username, password, group_id, mac):
    body = json.dumps({
          "ERSEndPoint": {
            "mac": mac,
            "staticProfileAssignment": False,
            "groupId": group_id,
            "staticGroupAssignment": True,
          }
        })
    url = "https://{}:9060/ers/config/endpoint".format(address)
    authcode = b64encode(b"{}:{}".format(username, password))
    authcode = authcode.decode("ascii")
    authstring = "Basic {}".format(authcode)
    headers = {
        "content-type": "application/json",
        "authorization": authstring,
        "cache-control": "no-cache"
    }
    response = requests.request("POST", url, headers=headers, data=body, verify=False)
    return response.headers


def pull_group(auth, group_name):
    log.info("gsuite_sync.ise.pull_group:\
 Called. Pulling group ID matching name ({})".format(group_name))
    uri = "/ers/config/endpointgroup?filter=name.EQ.{}".format(group_name)
    response = auth.get(uri)
    data = json.loads(response.text)
    for group in data["SearchResult"]["resources"]:
        if group["name"] == group_name:
            log.info("gsuite_sync.ise.pull_group:\
 Found matching ISE group ID ({})".format(group["id"]))
            log.debug("gsuite_sync.ise.pull_group:\
 Matching ISE Group Data:\n{}".format(
                     json.dumps(group, indent=4)))
            return group
    raise Exception("Cannot find ISE group ({})".format(group_name))


def pull_all_endpoints(auth, cache=True):
    endpoints = []
    #########################################################
    if cache:
        if os.path.isfile("ise_cache.json"):
            f = open("ise_cache.json")
            data = json.loads(f.read())
            f.close()
            return data
    #########################################################
    page = 1
    response = auth.get("/ers/config/endpoint?size=100&page={}".format(
        str(page)))
    data = json.loads(response.text)
    endpoints += data["SearchResult"]["resources"]
    log.info("gsuite_sync.ise.pull_all_endpoints:\
 Inventoried ({}/{}) endpoints so far".format(
        len(endpoints),
        data["SearchResult"]["total"]))
    try:
        while "nextPage" in data["SearchResult"]:
            page += 1
            response = auth.get("/ers/config/endpoint?size=100&page={}".format(
                str(page)))
            data = json.loads(response.text)
            endpoints += data["SearchResult"]["resources"]
            log.info("gsuite_sync.ise.pull_all_endpoints:\
 Inventoried ({}/{}) endpoints so far".format(
                len(endpoints),
                data["SearchResult"]["total"]))
        bulklog.info("gsuite_sync.ise.pull_all_endpoints:\
 All Endpoints:\n{}".format(json.dumps(endpoints, indent=4)))
    except KeyboardInterrupt:
        log.warning("gsuite_sync.ise.pull_all_endpoints:\
 Stopped, returning the ({}) endpoints we have so far".format(len(endpoints)))
    #########################################################
    f = open("ise_cache.json", "w")
    f.write(json.dumps(endpoints, indent=4))
    f.close()
    #########################################################
    return endpoints


def pull_group_endpoints(auth, group):
    endpoints = []
    page = 1
    response = auth.get("/ers/config/endpoint?filter=groupId.EQ.{}&size=100&page={}".format(
        group["id"],
        str(page)))
    data = json.loads(response.text)
    endpoints += data["SearchResult"]["resources"]
    log.info("gsuite_sync.ise.pull_group_endpoints:\
 Inventoried ({}/{}) endpoints so far".format(
        len(endpoints),
        data["SearchResult"]["total"]))
    try:
        while "nextPage" in data["SearchResult"]:
            page += 1
            response = auth.get("/ers/config/endpoint?filter=groupId.EQ.{}&size=100&page={}".format(
                group["id"],
                str(page)))
            data = json.loads(response.text)
            endpoints += data["SearchResult"]["resources"]
            log.info("gsuite_sync.ise.pull_group_endpoints:\
 Inventoried ({}/{}) endpoints so far".format(
                len(endpoints),
                data["SearchResult"]["total"]))
        bulklog.info("gsuite_sync.ise.pull_group_endpoints:\
 All Endpoints:\n{}".format(json.dumps(endpoints, indent=4)))
    except KeyboardInterrupt:
        log.warning("gsuite_sync.ise.pull_group_endpoints:\
 Stopped, returning the ({}) endpoints we have so far".format(len(endpoints)))
    return endpoints


def bulk_update(auth, group, in_ise_devices):
    log.info("gsuite_sync.ise.bulk_update:\
 Pushing ({}) endpoint updates to ISE".format(
        len(in_ise_devices)))
    endpoints = ""
    for device in in_ise_devices:
        endpoint = """            <ns4:endpoint id="{}" name="{}" xmlns:ers="ers.ise.cisco.com" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:ns4="identity.ers.ise.cisco.com">
                <link rel="self" href="{}" type="application/xml"></link>
                <groupId>{}</groupId>
                <mac>{}</mac>
                <staticGroupAssignment>true</staticGroupAssignment>
                <staticProfileAssignment>false</staticProfileAssignment>
            </ns4:endpoint>
""".format(
            device["endpoint"]["id"],
            device["endpoint"]["name"],
            device["endpoint"]["link"]["href"],
            group["id"],
            device["endpoint"]["name"],
            )
        endpoints += endpoint
    data = """<?xml version="1.0" encoding="utf-8"?>
<ns4:endpointBulkRequest xmlns:ns8="network.ers.ise.cisco.com" resourceMediaType="vnd.com.cisco.ise.identity.endpoint.1.0+xml" operationType="update" xmlns:ers="ers.ise.cisco.com" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:ns5="trustsec.ers.ise.cisco.com" xmlns:ns4="identity.ers.ise.cisco.com" xmlns:ns7="anc.ers.ise.cisco.com" xmlns:ns6="sxp.ers.ise.cisco.com">
	<ns4:resourcesList>
{}	</ns4:resourcesList>
</ns4:endpointBulkRequest>""".format(endpoints)
    bulklog.info("gsuite_sync.ise.bulk_update:\
 Bulk Data: {}".format(data))
    response = auth.put("/ers/config/endpoint/bulk/submit", data)
    log.info("gsuite_sync.ise.bulk_update:\
 ISE returned bulk job URL: {}".format(response.headers["Location"]))
    return response


def bulk_create(auth, group, devices):
    log.info("gsuite_sync.ise.bulk_create:\
 Pushing ({}) endpoint creations to ISE".format(
        len(devices)))
    endpoints = ""
    for device in devices:
        endpoint = """            <ns4:endpoint>
                <groupId>{}</groupId>
                <mac>{}</mac>
                <staticGroupAssignment>true</staticGroupAssignment>
                <staticProfileAssignment>false</staticProfileAssignment>
            </ns4:endpoint>
""".format(group["id"], device["macAddress"])
        endpoints += endpoint
    data = """<?xml version="1.0" encoding="utf-8"?>
<ns4:endpointBulkRequest xmlns:ns8="network.ers.ise.cisco.com" resourceMediaType="vnd.com.cisco.ise.identity.endpoint.1.0+xml" operationType="create" xmlns:ers="ers.ise.cisco.com" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:ns5="trustsec.ers.ise.cisco.com" xmlns:ns4="identity.ers.ise.cisco.com" xmlns:ns7="anc.ers.ise.cisco.com" xmlns:ns6="sxp.ers.ise.cisco.com">
	<ns4:resourcesList>
{}	</ns4:resourcesList>
</ns4:endpointBulkRequest>""".format(endpoints)
    response = auth.put("/ers/config/endpoint/bulk/submit", data)
    log.info("gsuite_sync.ise.bulk_create:\
 ISE returned bulk job URL: {}".format(response.headers["Location"]))
    return response


def lookup_endpoint_id(auth, mac):
    log.info("gsuite_sync.ise.lookup_endpoint_id:\
 Looking up ISE ID for MAC address ({})".format(mac))
    if ":" not in mac:
        mac = convert_mac(mac)
    response = auth.get("/ers/config/endpoint?filter=mac.EQ.{}".format(mac))
    data = json.loads(response.text)
    id = data["SearchResult"]["resources"][0]["id"]
    log.info("gsuite_sync.ise.lookup_endpoint_id:\
 ISE MAC address ({}) resolved to ISE ID ({})".format(mac, id))
    return id


def update_mac(auth, group, mac):
    if type(mac) == dict:
        mac = mac["macAddress"]
    log.info("gsuite_sync.ise.update_mac:\
 Running an update in ISE for MAC address ({})".format(mac))
    id = lookup_endpoint_id(auth, mac)
    data = json.dumps({
          "ERSEndPoint": {
            "mac": mac,
            "staticProfileAssignment": False,
            "groupId": group["id"],
            "staticGroupAssignment": True,
          }
        }, indent=4)
    response = auth.put("/ers/config/endpoint/{}".format(id), data)
    log.info("gsuite_sync.ise.update_mac:\
 ISE responded with ({}) to update request".format(response.status_code))
    bulklog.info("gsuite_sync.ise.update_mac:\
 ISE response data:\n{}".format(response.text))


def create_mac(auth, group, device):
    log.info("gsuite_sync.ise.create_mac:\
 Pushing a create to ISE with MAC address ({})".format(device["macAddress"]))
    data = json.dumps({
          "ERSEndPoint": {
            "mac": convert_mac(device["macAddress"]),
            "staticProfileAssignment": False,
            "groupId": group["id"],
            "staticGroupAssignment": True,
          }
        }, indent=4)
    response = auth.post("/ers/config/endpoint", data)
    log.info("gsuite_sync.ise.create_mac:\
 ISE responded with ({}) to create request".format(response.status_code))
    bulklog.info("gsuite_sync.ise.create_mac:\
 ISE response data:\n{}".format(response.text))


def convert_mac(mac):
    if len(mac) != 12:
        raise Exception("Mac length incorrect ({})".format(mac))
    result = "{}{}:{}{}:{}{}:{}{}:{}{}:{}{}".format(
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
        mac[6],
        mac[7],
        mac[8],
        mac[9],
        mac[10],
        mac[11]
    ).upper()
    log.info("gsuite_sync.ise.convert_mac:\
 Converted MAC address from ({}) to ({})".format(mac, result))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
                        '-ia', "--ise_address",
                        help="ISE Address",
                        metavar='ADDRESS/IP',
                        dest="ise_address")
    parser.add_argument(
                        '-iu', "--ise_username",
                        help="ISE Username",
                        metavar='USERNAME',
                        dest="ise_username")
    parser.add_argument(
                        '-ip', "--ise_password",
                        help="ISE Password",
                        metavar='PASSWORD',
                        dest="ise_password")
    parser.add_argument(
                        '-ig', "--ise_group",
                        help="ISE Endpoint Group Name",
                        metavar='GROUP_NAME',
                        dest="ise_group")
    parser.add_argument(
                        '-cm', "--create_mac",
                        help="Create MAC Endpoint in the Group",
                        metavar='MAC_ADDRESS',
                        dest="create_mac")
    args = parser.parse_args()
    auth = ise_auth(
        args.ise_address,
        args.ise_username,
        args.ise_password
    )
    print(json.dumps(pull_group(auth, args.ise_group), indent=4))
