#!/usr/bin/python

from __future__ import print_function
from apiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow


# Built-In Libraries
from builtins import input
import pickle
import argparse
import json
import logging
import os


SCOPES = ['https://www.googleapis.com/auth/admin.directory.device.chromeos']


def main():
    print("Visit https://developers.google.com/admin-sdk/directory/v1/quickstart/python")
    print("    Enable the directory API and download the credentials.json file")
    credentials_file = input("File Path of the credentials.json file: ")
    flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
    print("Finding page for token creation")
    creds = flow.run_local_server()
    creds_data = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
        }
    creds_data = json.dumps(creds_data, indent=4)
    print("Token Data:\n{}".format(creds_data))
    token_file = input("File path to create new token file: ")
    with open(token_file, "wb") as new_cred_file:
        pickle.dump(creds, new_cred_file)
    print("Done!")


if __name__ == "__main__":
    main()
