#!/usr/bin/python

"""
Main gsuite_sync application. Run from the command-line to perform the sync
function between GSuite and ISE.
"""

# Built-In Libraries
import os
import sys
import json
import logging
import argparse

# GSuite_Sync Libraries
from . import gsuite_pull


# log (console) is used to output data to the console properly formatted
log = logging.getLogger("console")
# datalog is used to output structured data without formatting
datalog = logging.getLogger("data")


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
    # Required arguments are needed to start the program
    required = parser.add_argument_group('Required Arguments')
    # Optional arguments are not required for the start of the program
    optional = parser.add_argument_group('Optional Arguments')
    # Misc arguments are meant for informational help-based arguments
    misc = parser.add_argument_group('Misc Arguments')
    misc.add_argument(
                        "-h", "--help",
                        help="show this help message and exit",
                        action="help")
    misc.add_argument(
                        "-v", "--version",
                        action="version",
                        version='GSuite_Sync v0.0.1')
    required.add_argument(
                        '-gc', "--gsuite_credential",
                        help="GSuite Credential File",
                        metavar='CRED_FILE',
                        dest="gsuite_credential")
    optional.add_argument(
                        '-d', "--debug",
                        help="""Set debug level (WARNING by default)
        Debug level INFO:  '-d'
        Debug level DEBUG: '-d'""",
                        dest="debug",
                        action='count')
    optional.add_argument(
                    '-l', "--logfile",
                    help="""File for logging output
Examples:
    '-l /home/user/logs/mylogfile.txt'""",
                    metavar='PATH',
                    dest="logfiles",
                    action="append")
    args = parser.parse_args()
    startlogs.append({
        "level": "debug",
        "message": "gsuite_sync._parse_args: Args returned:\n{}".format(
            json.dumps(args.__dict__, indent=4)
            )
        })
    return args


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
    # datalog logging level is always info as it is not used for
    #  debugging or reporting warning and errors
    datalog.setLevel(logging.INFO)
    # consoleHandler is used for outputting to the console for log and modlog
    consoleHandler = logging.StreamHandler()
    # dataHandler is used to write to std.out so the output data can be piped
    #  into other applications without being mangled by informational logs
    dataHandler = logging.StreamHandler(sys.stdout)
    # Standard format for informational logging
    format = logging.Formatter(
        "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s"
        )
    # Standard format used for console (non-std.out) output
    consoleHandler.setFormatter(format)
    # Console output (non-std.out) handler used on log
    log.addHandler(consoleHandler)
    # std.out handler used on datalog
    datalog.addHandler(dataHandler)
    # If any logfiles were pased in the arguments
    if args.logfiles:
        for file in args.logfiles:
            # Create a handler, set the format, and apply that handler to
            #  log and modlog
            fileConsoleHandler = logging.FileHandler(file)
            fileDataHandler = logging.FileHandler(file)
            fileConsoleHandler.setFormatter(format)
            log.addHandler(fileConsoleHandler)
            datalog.addHandler(fileDataHandler)
    # Set debug levels based on how many "-d" args were parsed
    if not args.debug:
        log.setLevel(logging.WARNING)
    elif args.debug == 1:
        log.setLevel(logging.INFO)
    elif args.debug == 2:
        log.setLevel(logging.DEBUG)
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


def _get_gsuite_devices(args):
    if not args.gsuite_credential:
        log.error("gsuite_sync._get_gsuite_credential:\
 GSuite credential required and not defined. Quitting")
        sys.exit()
    else:
        log.info("gsuite_sync._get_gsuite_credential:\
 Calling gsuite_pull.pull_devices with credential file ({})".format(
                 args.gsuite_credential))
        return gsuite_pull.pull_devices(args.gsuite_credential)


def main():
    """
    gsuite_sync.main is the main application function.
    """
    startlogs = []  # Logs drop here until the logging facilities are ready
    args = _parse_args(startlogs)
    _start_logging(startlogs, args)
    devices = _get_gsuite_devices(args)


if __name__ == "__main__":
    main()
