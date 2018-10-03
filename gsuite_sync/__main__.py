#!/usr/bin/python

"""
Main gsuite_sync application. Run from the command-line to perform the sync
function between GSuite and ISE.
"""

# Built-In Libraries
import os
import re
import sys
import json
import logging
import argparse
import time

# GSuite_Sync Libraries
from . import google
from . import ise


# log (console) is used to output data to the console properly formatted
log = logging.getLogger("console")
# bulklog is used to output structured data without formatting
bulklog = logging.getLogger("bulk")
# report is used to output final data
report = logging.getLogger("report")


def _parse_args(startlogs):
    """
    gsuite_sync._parse_args uses the argparse library to parse the arguments
    entered at the command line to get user-input information.
    """
    startlogs.append({
        "level": "debug",
        "message": "gsuite_sync._parse_args: Starting parsing of arguments"
        })
    parser = argparse.ArgumentParser(
        description='GSuite_Sync -\
 Sync Chromebook MAC addresses from your GSuite into Cisco ISE ',
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False)
    # Misc arguments are meant for informational help-based arguments
    misc = parser.add_argument_group('Misc Arguments')
    # Required arguments are needed to start the program
    required = parser.add_argument_group('Required Arguments')
    # Optional arguments are not required for the start of the program
    optional = parser.add_argument_group('Optional Arguments')
    # Misc arguments are meant for informational help-based arguments
    actions = parser.add_argument_group('Action Arguments')
    misc.add_argument(
        "-h", "--help",
        help="show this help message and exit",
        action="help")
    misc.add_argument(
        "-v", "--version",
        action="version",
        version='GSuite_Sync v0.0.4')
    required.add_argument(
        '-gc', "--gsuite_credential",
        help="GSuite Credential File",
        metavar='CREDENTIAL_FILE',
        dest="gsuite_credential")
    optional.add_argument(
        '-gm', "--gsuite_path_match",
        help="GSuite Object Path Match Pattern",
        metavar='REGEX',
        dest="gsuite_path_match")
    required.add_argument(
        '-ia', "--ise_address",
        help="ISE DNS or IP Address",
        metavar='IP/ADDRESS',
        dest="ise_address")
    required.add_argument(
        '-iu', "--ise_username",
        help="ISE Login Username",
        metavar='USERNAME',
        dest="ise_username")
    required.add_argument(
        '-ip', "--ise_password",
        help="ISE Login Password",
        metavar='PASSWORD',
        dest="ise_password")
    required.add_argument(
        '-ig', "--ise_group",
        help="ISE Target Endpoint Group",
        metavar='GROUP_NAME',
        dest="ise_group")
    optional.add_argument(
        '-c', "--config_file",
        help="Config File Path",
        metavar='CONFIG_FILE',
        dest="config_file")
    optional.add_argument(
        '-l', "--logfiles",
        help="Log File Path",
        metavar='LOG_FILE',
        dest="logfiles")
    optional.add_argument(
        '-d', "--debug",
        help="""Set debug level (WARNING by default)
        Debug level INFO:  '-d'
        Debug level DEBUG: '-d'""",
        dest="debug",
        action='count')
    actions.add_argument(
        '-fs', "--full_sync",
        help="Perform full sync of GSuite MACs to ISE Group",
        dest="full_sync",
        action='store_true')
    actions.add_argument(
        '-um', "--update_mac",
        help="Push an individual MAC to the ISE Group",
        metavar='MAC_ADDRESS',
        dest="update_mac")
    actions.add_argument(
        '-us', "--update_serial",
        help="Lookup a device's MAC and update it in the ISE Group",
        metavar='SERIAL_NUMBER',
        dest="update_serial")
    actions.add_argument(
        '-m', "--maintain",
        help="maintain pushing devices",
        dest="maintain",
        action='store_true')
    args = parser.parse_args()
    _import_config_file(startlogs, args)
    startlogs.append({
        "level": "debug",
        "message": "gsuite_sync._parse_args: Complete Args:\n{}".format(
            json.dumps(args.__dict__, indent=4)
            )
        })
    return args


def _import_config_file(startlogs, args):
    if not args.config_file:
        startlogs.append({
            "level": "info",
            "message": "gsuite_sync._import_config_file:\
No config file defined. All info must be present in command arguments"
            })
    elif not os.path.isfile(args.config_file):
        startlogs.append({
            "level": "warning",
            "message": "gsuite_sync._import_config_file:\
 Config file ({}) does not exist! Ignoring it."
            })
    else:
        f = open(args.config_file, "r")
        data = json.loads(f.read())
        f.close()
        for item in data:
            if item in args.__dict__:
                if not args.__dict__[item]:
                    args.__dict__[item] = data[item]
            else:
                args.__dict__[item] = data[item]


def _start_logging(startlogs, args):
    """
    gsuite_sync._start_logging configures the logging facilities (console,
    and data) with the appropriate handlers and formats, creates the logfile
    handlers if any were requested, and sets the logging levels based on how
    verbose debugging was requested to be in the args.
    """
    startlogs.append({
        "level": "debug",
        "message": "gsuite_sync._start_logging: Configuring logging"
        })
    # bulklog logging level is always info as it is not used for
    #  debugging or reporting warning and errors
    bulklog.setLevel(logging.INFO)
    # Reporting is always done as info or higher
    report.setLevel(logging.INFO)
    # consoleHandler is used for outputting to the console for log and modlog
    consoleHandler = logging.StreamHandler()
    # bulkHandler is used to write to std.out so the output data can be piped
    #  into other applications without being mangled by informational logs
    bulkHandler = logging.StreamHandler()
    # Standard format for informational logging
    format = logging.Formatter(
        "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s"
        )
    # Standard format used for console output
    consoleHandler.setFormatter(format)
    # Standard format used for bulk output
    bulkHandler.setFormatter(format)
    # Console output (non-std.out) handler used on log
    log.addHandler(consoleHandler)
    # Reporting done same as log
    report.addHandler(consoleHandler)
    # std.out handler used on bulklog
    bulklog.addHandler(bulkHandler)
    # If any logfiles were pased in the arguments
    if args.logfiles:
        for file in args.logfiles:
            # Create a handler, set the format, and apply that handler to
            #  log and modlog
            fileConsoleHandler = logging.FileHandler(file)
            fileDataHandler = logging.FileHandler(file)
            fileConsoleHandler.setFormatter(format)
            fileDataHandler.setFormatter(format)
            log.addHandler(fileConsoleHandler)
            bulklog.addHandler(fileDataHandler)
            report.addHandler(fileDataHandler)
    # Set debug levels based on how many "-d" args were parsed
    if not args.debug:
        log.setLevel(logging.WARNING)
        bulklog.setLevel(logging.WARNING)
    elif args.debug == 1:
        log.setLevel(logging.INFO)
        bulklog.setLevel(logging.WARNING)
    elif args.debug == 2:
        log.setLevel(logging.DEBUG)
        bulklog.setLevel(logging.WARNING)
    elif args.debug == 3:
        log.setLevel(logging.DEBUG)
        bulklog.setLevel(logging.INFO)
    # Mappings for startlog entries to be passed properly into the log facility
    maps = {
           "debug": logging.DEBUG,
           "info": logging.INFO,
           "warning": logging.WARNING,
           "error": logging.ERROR,
           "critical": logging.CRITICAL
    }
    # Pass the startlogs into the loggin facility under the proper level
    for msg in startlogs:
        log.log(maps[msg["level"]], msg["message"])


def filter_devices(devices, regex):
    if not regex:
        log.info("gsuite_sync.filter_devices:\
 No filter set. Returning all ({}) devices".format(len(devices)))
        return devices
    result = []
    removed = 0
    added = 0
    log.info("gsuite_sync.filter_devices:\
 Filtering devices using ({})".format(regex))
    for device in devices:
        if re.search(regex, device["orgUnitPath"]):
            result.append(device)
            added += 1
        else:
            removed += 1
    log.info("gsuite_sync.filter_devices:\
 Filtered out ({}) devices and kept ({})".format(removed, added))
    return result


def strip_no_mac(devices):
    nomac = 0
    result = []
    for device in devices:
        if "macAddress" in device:
            result.append(device)
        else:
            nomac += 1
    log.info("gsuite_sync.strip_no_mac:\
 Stripped ({}) devices with no MAC. Returning ({}) devices".format(
        nomac, len(result)))
    return result


def reconcile_macs(devices, endpoints):
    log.info("gsuite_sync.reconcile_macs:\
 Reconciling ({}) devices and ({}) endpoints".format(
                                                     len(devices),
                                                     len(endpoints)))
    ###################################
    devicebymac = {}
    endpointbymac = {}
    nomac = 0
    for device in devices:
        if "macAddress" in device:
            mac = device["macAddress"]
            devicebymac.update({mac: device})
        else:
            nomac += 1
    for endpoint in endpoints:
        mac = endpoint["name"]
        mac = mac.replace(":", "")
        mac = mac.lower()
        endpointbymac.update({mac: endpoint})
    ###################################
    in_ise = []
    not_in_ise = []
    for devicemac in devicebymac:
        if devicemac in endpointbymac:
            devicebymac[devicemac].update({
                "endpoint": endpointbymac[devicemac]
                })
            in_ise.append(devicebymac[devicemac])
        else:
            not_in_ise.append(devicebymac[devicemac])
    log.info("gsuite_sync.reconcile_macs:\
 Devices found in ISE: {}".format(len(in_ise)))
    log.info("gsuite_sync.reconcile_macs:\
 Devices NOT found in ISE: {}".format(len(not_in_ise)))
    log.info("gsuite_sync.reconcile_macs:\
 Devices without a MAC listed: {}".format(nomac))
    return (in_ise, not_in_ise)


def pop_qty(qty, source):
    result = []
    while len(result) < qty:
        if len(source) == 0:
            break
        else:
            result.append(source.pop(0))
    return result


def update(iseauth, group, in_ise, not_in_ise):
    while not_in_ise:
        push_devices = pop_qty(500, not_in_ise)
        ise.bulk_update(iseauth, group, push_devices)
        time.sleep(10)
    while in_ise:
        push_devices = pop_qty(500, not_in_ise)
        ise.bulk_update(iseauth, group, push_devices)
        time.sleep(10)


def get_mac_by_serial(google_auth, serial):
    serial = serial.upper()
    devices = google.pull_devices(google_auth)
    for device in devices:
        if device["serialNumber"] == serial:
            return device
    raise Exception("Serial Number ({}) Not Found!".format(serial))


def check_group_membership(devices, group_endpoints):
    log.info("gsuite_sync.check_group_membership:\
 Checking group membership for ({}) devices".format(len(devices)))
    ###################################
    devicebymac = {}
    endpointbymac = {}
    nomac = 0
    for device in devices:
        if "macAddress" in device:
            mac = device["macAddress"]
            devicebymac.update({mac: device})
        else:
            nomac += 1
    for endpoint in group_endpoints:
        mac = endpoint["name"]
        mac = mac.replace(":", "")
        mac = mac.lower()
        endpointbymac.update({mac: endpoint})
    ###################################
    missing_devices = []
    for dmac in devicebymac:
        if dmac not in endpointbymac:
            missing_devices.append(devicebymac[dmac])
    group_extras = []
    for emac in endpointbymac:
        if emac not in devicebymac:
            group_extras.append(endpointbymac[emac])
    log.info("gsuite_sync.check_group_membership:\
 Returning ({}) missing devices".format(len(missing_devices)))
    return (missing_devices, group_extras)


def maintain(args, google_auth, ise_auth, devices):
    group = ise.pull_group(ise_auth, args.ise_group)
    try:
        updated_devices = google.pull_devices(google_auth, cache=False)
    except Exception as e:
        log.exception('gsuite_sync.maintain:\
 Exception raised connecting to Google. Skipping')
        updated_devices = devices
    updated_devices = filter_devices(updated_devices, args.gsuite_path_match)
    updated_devices = strip_no_mac(updated_devices)
    new_devices = []
    for device in updated_devices:
        if device not in devices:
            new_devices.append(device)
    if new_devices:
        report.info("gsuite_sync.maintain:\
 Pushing ({}) new devices".format(
                                    len(new_devices),
                                    json.dumps(new_devices, indent=4)))
        for device in new_devices:
            try:
                ise.create_mac(ise_auth, group, device)
                report.info("gsuite_sync.maintain:\
 Device ({}) ({}) pushed as new device".format(
                                                device["macAddress"],
                                                device["serialNumber"]))
            except Exception:
                report.info("gsuite_sync.maintain:\
 Updating ({}) ({}) since it is already an endpoint".format(
                                                    device["macAddress"],
                                                    device["serialNumber"]))
                try:
                    ise.update_mac(ise_auth, group, device)
                except Exception:
                    report.exception("gsuite_sync.maintain:\
 Failed to update ({}) ({}) as ISE seems to be offline".format(
                                                device["macAddress"],
                                                device["serialNumber"]))
                    return devices
        report.info("gsuite_sync.maintain:\
 Pushed ({}) new devices".format(
                                 len(new_devices),
                                 json.dumps(new_devices, indent=4)))
    report.info("gsuite_sync.maintain:\
 Returning ({}) total devices".format(len(updated_devices)))
    return updated_devices


def full_sync(args, google_auth, ise_auth):
    group = ise.pull_group(ise_auth, args.ise_group)
    devices = google.pull_devices(google_auth, cache=False)
    devices = filter_devices(devices, args.gsuite_path_match)
    devices = strip_no_mac(devices)
    endpoints = ise.pull_all_endpoints(ise_auth, cache=False)
    in_ise, not_in_ise = reconcile_macs(devices, endpoints)
    while not_in_ise:
        push_devices = pop_qty(500, not_in_ise)
        ise.bulk_create(ise_auth, group, push_devices)
        time.sleep(10)
    while in_ise:
        push_devices = pop_qty(500, in_ise)
        ise.bulk_update(ise_auth, group, push_devices)
        time.sleep(10)
    report.info("gsuite_sync.full_sync:\
 Processed ({}) devices and ({}) endpoints".format(
                                                   len(devices),
                                                   len(endpoints)))


def main():
    """
    gsuite_sync.main is the main application function.
    """
    startlogs = []  # Logs drop here until the logging facilities are ready
    args = _parse_args(startlogs)
    _start_logging(startlogs, args)
    google_auth = google.get_service(args.gsuite_credential)
    ise_auth = ise.ise_auth(
        args.ise_address,
        args.ise_username,
        args.ise_password
    )
    if args.update_mac:
        group = ise.pull_group(ise_auth, args.ise_group)
        ise.update_mac(ise_auth, group, args.update_mac)
    if args.update_serial:
        device = get_mac_by_serial(google_auth, args.update_serial)
        group = ise.pull_group(ise_auth, args.ise_group)
        ise.update_mac(ise_auth, group, device)
    if args.full_sync:
        full_sync(args, google_auth, ise_auth)
    if args.maintain:
        devices = google.pull_devices(google_auth)
        devices = filter_devices(devices, args.gsuite_path_match)
        devices = strip_no_mac(devices)
        while True:
            devices = maintain(args, google_auth, ise_auth, devices)
            time.sleep(10)


if __name__ == "__main__":
    main()
