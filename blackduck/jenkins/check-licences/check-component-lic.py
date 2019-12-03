#!/usr/bin/env python3

import argparse
import csv
import json
import logging
import mdutils
import os
import pathlib
import requests
import sys

from blackduck.HubRestApi import HubInstance
from mdutils.mdutils import MdUtils
from mdutils.tools.tools import TextUtils
from pathlib import Path

logger = logging.getLogger('blackduck/check-component-lic')
logger.setLevel(logging.DEBUG)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
ch = logging.StreamHandler()
logger.addHandler(ch)

class ComponentLicenseChecker:
    def __init__(self, product, version, cred_file, report_dir):
        self.product = product
        self.version = version

        # Connect to Black Duck
        creds = json.load(cred_file)
        logger.debug(f"Connecting to Black Duck hub {creds['url']}")
        self.hub = HubInstance(creds["url"], creds["username"], creds["password"], insecure=True)

        self.report_dir = Path(report_dir)
        self.init_reports()

    def init_reports(self):
        """
        Prepares report directory for report content
        """

        # Dir where global license info is kept
        self.lic_data_dir = self.report_dir / "license-data"
        self.lic_data_dir.mkdir(exist_ok=True)

        # Dir where the per-product-version report is kept
        prodver_report_dir = self.report_dir / self.product / self.version
        prodver_report_dir.mkdir(parents=True, exist_ok=True)

        # The per-product-version report markdown file itself
        self.report_index = MdUtils(
            file_name=str(prodver_report_dir / "README"),
            title=f"Suspect License Report for {self.product} {self.version}"
        )

        # Initialize license table headers
        self.lic_table = ["Component", "Version", "License(s)"]

    def close_reports(self):
        """
        Finalizes report directory
        """

        self.report_index.new_table(
            columns=3,
            rows=len(self.lic_table) // 3,
            text=self.lic_table,
            text_align="left"
        )
        self.report_index.create_md_file()

    def _get_lic_text_file(self, lic_id):
        """
        Returns the pathlib object for the license text file for lic_id
        """

        return self.lic_data_dir / (lic_id + ".txt")

    def _get_lic_name_file(self, lic_id):
        """
        Returns the pathlib object for the license name file for lic_id
        """

        return self.lic_data_dir / (lic_id + "-name.txt")

    def save_lic_files(self, lic_id):
        """
        Creates <lic>.txt and <lic>-name.txt files in report directory.
        Returns saved license name.
        """

        lic_text_file = self._get_lic_text_file(lic_id)
        if not lic_text_file.exists():
            logger.debug(f"Getting license text for {lic_id} from Black Duck hub")
            response = self.hub.execute_get(
                self.hub.get_urlbase() + "/api/licenses/" + lic_id + "/text"
            )
            response.encoding = 'utf-8'
            with lic_text_file.open("w") as o:
                o.write(response.json()['text'])

        lic_name_file = self._get_lic_name_file(lic_id)
        if not lic_name_file.exists():
            logger.debug(f"Getting license name for {lic_id} from Black Duck hub")
            response = self.hub.execute_get(
                self.hub.get_urlbase() + "/api/licenses/" + lic_id
            )
            response.encoding = 'utf-8'
            lic_name = response.json()['name']
            with lic_name_file.open("w") as o:
                o.write(lic_name)
        else:
            with lic_name_file.open() as o:
                lic_name = o.readline()

        return lic_name

    def check_and_report_component(self, comp):
        """
        Check a component's license(s). If not OK, write a license report.
        Returns: true if all OK
        """
        # If it's Reviewed in Black Duck, it's presumed OK
        if comp['Review status'] == "REVIEWED":
            logger.debug (f"Skipping {comp['Component name']} {comp['Component version name']} because it's reviewed")
            return True

        # Pull out all known license IDs and see if *any* are approved
        lics = comp['License ids'].split(',')
        if any(item in self.ok_lics for item in lics):
            logger.debug (f"Skipping {comp['Component name']} {comp['Component version name']} because license is OK")
            return True

        # License NOT OK - warn and write report entry
        logger.warn (f"WARNING: {comp['Component name']} {comp['Component version name']} has suspect license {comp['License names']}")
        lic_links = []
        for lic_id in lics:
            lic_links.append(
                TextUtils.text_external_link(
                    self.save_lic_files(lic_id),
                    "../../license-data/" + lic_id + ".txt"
                )
            )

        # Save details for report table
        self.lic_table.extend([
            comp['Component name'],
            comp['Component version name'],
            ", ".join(lic_links)
        ])

        return False

    def check_licenses(self):
        """
        Main processing loop
        """

        # Download acceptable licenses JSON
        logger.debug("Downloading acceptable licenses JSON file")
        response = requests.get("https://raw.githubusercontent.com/couchbase/product-metadata/master/All-Products/blackduck/pre-approved-licenses.json")
        ok_lics_data = response.json()
        self.ok_lics = ok_lics_data.keys()

        # Download current CSV report
        logger.debug(f"Downloading CSV report for {self.product} {self.version}")
        csv_url = f"https://raw.githubusercontent.com/couchbase/product-metadata/master/{self.product}/blackduck/{self.version}/components.csv"
        all_ok_lics = True
        logger.debug(f"Checking licenses for {self.product} {self.version}")
        with requests.get(csv_url, stream=True) as r:
            comps = csv.DictReader(line.decode('utf-8') for line in r.iter_lines())

            for comp in comps:
                all_ok_lics &= self.check_and_report_component(comp)

        self.close_reports()

        if all_ok_lics:
            logger.info ("All licenses are clean or approved!")
            return True
        else:
            return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Produce filtered list of components with suspect licenses'
    )
    parser.add_argument('product', help='Product from Black Duck server')
    parser.add_argument('version', help='Version of <product>')
    parser.add_argument('-c', '--credentials', required=True,
                        type=argparse.FileType('r', encoding='UTF-8'),
                        help='Path to Black Duck server credentials JSON file')
    parser.add_argument('-d', '--report-directory', type=str, required=True,
                        help='Path to output report directory')

    args = parser.parse_args()

    if not os.path.isdir(args.report_directory):
        logger.error(f"Output report directory does not exist: {args.report_directory}")
        sys.exit(1)

    checker = ComponentLicenseChecker(args.product, args.version, args.credentials, args.report_directory)
    if not checker.check_licenses():
        sys.exit(1)