#!/usr/bin/env python3

import sys
import json
import logging
from collections import defaultdict
from pathlib import Path
from itertools import groupby
import urllib
from blackduck import Client
import constants

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class BlackduckClient:
    def __init__(self):
        '''
        Initiate Black Duck connection.
        '''
        creds_file = Path.home() / '.ssh/blackduck-creds.json'
        if creds_file.exists():
            with open(creds_file) as f:
                bd_creds = json.load(f)
        else:
            logging.error('Unable to locate blackduck-creds.json')
            sys.exit(1)

        self.base_url = bd_creds['url']
        self.hub_client = Client(
            token=bd_creds['token'],
            base_url=bd_creds['url'],
            verify=False,
            timeout=30.0,
            retries=5
        )

    def _get_resource_by_name(self, key, resource_type,
                              resource_name, parent=None):
        '''Helper function to query and return single resource by name'''
        params = {
            'q': [f"{key}:{resource_name}"]
        }
        result = [r for r in self.hub_client.get_resource(
            resource_type,
            parent=parent,
            params=params)
            if r[key] == resource_name]
        if len(result) != 1:
            raise ValueError(
                f"Expected one {resource_type} of {resource_name}, but found {len(result)}")
        return result[0]

    def _fetch_all_links(self, url, headers=None):
        '''Helper function to fetch paginated data from the given URL'''
        all_items = []
        while url:
            result = self.hub_client.get_json(url, headers=headers)
            # Add items from the current page to the list
            all_items.extend(result.get('items', []))

            # Look for the "paging-next" link in the links
            url = next(
                (link['href'] for link in result.get(
                    '_meta',
                    {}).get(
                    'links',
                    []) if link.get('rel') == 'paging-next'),
                None)
        return all_items

    def _build_link(self, x):
        '''Helper function to build vulnerability link string'''
        if 'vuln' not in x:
            return None
        parts = []
        if x['bdsa_id'] and x['bdsa_link']:
            parts.append(f"[{x['bdsa_id']}|{x['bdsa_link']}]")
        if x['cve_id'] and x['cve_link']:
            parts.append(f"[{x['cve_id']}|{x['cve_link']}]")
        return f"{x['severity']}:[ {' '.join(parts)} ]" if parts else None

    def _process_vulnerability_detail(self, vuln_id):
        '''Process vulnerability details from BlackDuck API and return structured data'''
        cve_link = cve_id = cve_severity = ''
        bdsa_link = bdsa_id = bdsa_severity = ''

        url = f"{self.base_url}/api/vulnerabilities/{vuln_id}"
        vuln_detail = self.hub_client.get_json(url)

        # Skip entries with null severity
        severity = vuln_detail.get('severity')
        if severity is None:
            logging.warning(
                f"Vulnerability {vuln_id} has null severity. Skipping.")
            return None

        # Skip entries with unknown source
        if vuln_detail['source'] not in ('BDSA', 'NVD'):
            logging.warning(
                f'Vulnerability {vuln_id} has unknown source: {vuln_detail["source"]}. Skipping.')
            return None

        if vuln_detail['source'] == 'NVD':
            cve_link = next(
                (x['href'] for x in vuln_detail['_meta']['links'] if x.get('rel') == 'nist'), '')
            bdsa_link = next((x['href'] for x in vuln_detail['_meta'][
                             'links'] if 'label' in x and x['label'] == 'BDSA'), '')
            cve_id = vuln_id
            cve_severity = severity
            if bdsa_link:
                bdsa_id = bdsa_link.split('/')[-1]
                bdsa_detail = self.hub_client.get_json(bdsa_link)
                bdsa_severity = bdsa_detail.get('severity')
                severity = bdsa_severity

        elif vuln_detail['source'] == 'BDSA':
            bdsa_link = vuln_detail['_meta']['href']
            bdsa_id = vuln_id
            bdsa_severity = severity
            bd_cve_link = next(
                (x['href'] for x in vuln_detail['_meta']['links']
                 if 'label' in x and x['label'] == 'NVD'), '')
            if bd_cve_link:
                cve_detail = self.hub_client.get_json(bd_cve_link)
                cve_link = next(
                    (x['href'] for x in cve_detail['_meta']['links']
                     if x['rel'] == 'nist'), '')
                cve_id = cve_link.split('/')[-1]
                cve_severity = cve_detail.get('severity')

        vuln_data = {
            'severity': severity,
            'cve_id': cve_id,
            'bdsa_id': bdsa_id,
            'cve_severity': cve_severity,
            'bdsa_severity': bdsa_severity,
            'cve_link': cve_link,
            'bdsa_link': bdsa_link,
            'vuln_detail': vuln_detail
        }
        return vuln_data

    def _group_entries(self, entries, group_key, sort_key,
                       base_fields, component_files=None):
        '''Generic method to group vulnerability entries by specified criteria'''
        grouped_entries = []

        entries.sort(
            key=sort_key,
            reverse=True if 'updatedDate' in str(sort_key) else False)

        for k, g in groupby(entries, key=group_key):
            comp_entries = list(g)
            comp_dict = {field: comp_entries[0][field]
                         for field in base_fields}

            comp_entries.sort(
                key=lambda x: constants.SEVERITY_LIST.index(
                    x['severity']))
            comp_dict['severity'] = comp_entries[0]['severity']

            comp_dict['bdsa_list'] = ','.join(
                sorted(set(x['bdsa_id']
                           for x in comp_entries
                           if x['bdsa_id'])))
            comp_dict['cve_list'] = ','.join(
                sorted(set(x['cve_id']
                           for x in comp_entries
                           if x['cve_id'])))
            comp_dict['links'] = '\n'.join(dict.fromkeys(
                filter(None, (self._build_link(x) for x in comp_entries))))

            if component_files is not None:
                comp_dict['files'] = component_files[comp_dict['componentVersion']]

            grouped_entries.append(comp_dict)

        return grouped_entries

    def get_project_by_name(self, project_name):
        '''Query project by name'''
        project = self._get_resource_by_name('name', 'projects', project_name)
        return project

    def get_project_version(self, project, version_name):
        '''Query project version by name'''
        version = self._get_resource_by_name(
            'versionName', 'versions', version_name, project)
        return version

    def is_version_archived(self, version):
        '''Check if a project version is Archived'''
        is_archived = False
        phase = version.get('phase', '')
        if phase.lower() == 'archived':
            logging.info(
                f'Version {version.get("versionName")} is in {phase} phase.'
                'No new scan will be produced.')
            is_archived = True
        else:
            logging.debug(
                f'Version {version.get("versionName")} is in {phase} phase.')

        return is_archived

    def get_bom_files(self, version):
        '''Produce a dictionary of files associated with components in a project version.'''
        component_files = defaultdict(list)
        local_file_prefix = 'file:///home/couchbase/workspace/blackduck-detect-scan/src/'
        version_url = version['_meta']['href']
        url = f"{version_url}/matched-files?limit=100"
        headers = {
            'Accept': 'application/vnd.blackducksoftware.bill-of-materials-6+json'}
        items = self._fetch_all_links(url, headers)

        for item in items:
            filepath = item.get('declaredComponentPath') or item.get(
                'uri', '')[len(local_file_prefix):]
            component_url = item['matches'][0]['component'].rsplit(
                '/origins', 1)[0]
            component_files[component_url].append(filepath)
        return component_files

    def group_vulnerability_entries(self, vuln_list, component_files):
        ''' Group vulnerability entries by component version.  '''
        return self._group_entries(
            entries=vuln_list,
            group_key=lambda x: x['componentVersion'],
            sort_key=lambda x: (x['componentVersion'], x['updatedDate']),
            base_fields=(
                'componentVersion',
                'componentName',
                'componentVersionName',
                'updatedDate'),
            component_files=component_files
        )

    def group_journal_entries(self, cve_entries):
        ''' Aggregate journal entries by component version.  '''
        return self._group_entries(
            entries=cve_entries,
            group_key=lambda x: (
                x['componentName'],
                x['componentVersionName']),
            sort_key=lambda x: (x['componentName'], x['componentVersionName']),
            base_fields=(
                'componentName',
                'componentVersionName',
                'updatedDate'),
            component_files=None
        )

    def get_bom_vulns(self, version):
        '''Retrieve vulnerabilities associated with a specific project version from Blackduck.'''
        vulns = []
        bom_url = f"{version['_meta']['href']}/vulnerable-bom-components?limit=100"
        headers = {
            'Accept': 'application/vnd.blackducksoftware.bill-of-materials-8+json'}
        items = self._fetch_all_links(bom_url, headers)
        vulns.extend(items)
        return vulns

    def prepare_vulnerability_entries(self, version):
        '''Prepare vulnerability entries for reporting.'''
        component_files = self.get_bom_files(version)
        entries = self.get_bom_vulns(version)

        vuln_list = []
        for entry in entries:
            vuln_id = entry['vulnerability']['vulnerabilityId']
            print(f'CVE: {vuln_id}')

            # Skip if CVE is in the exclusion list
            if vuln_id in (constants.EXCLUDED_CVE_LIST,
                           constants.EXCLUDED_BDSA_LIST):
                logging.info(
                    f"Vulnerability {vuln_id} is on the excluded list. Skipping.")
                continue

            # Process vulnerability details using helper method
            vuln_data = self._process_vulnerability_detail(vuln_id)
            if vuln_data is None or not vuln_data:
                continue

            vuln_list.append({
                'componentVersion': entry['componentVersion'],
                'componentName': entry['componentName'],
                'componentVersionName': entry['componentVersionName'],
                'severity': vuln_data['severity'],
                'cve_id': vuln_data['cve_id'],
                'bdsa_id': vuln_data['bdsa_id'],
                'cve_severity': vuln_data['cve_severity'],
                'bdsa_severity': vuln_data['bdsa_severity'],
                'cve_link': vuln_data['cve_link'],
                'bdsa_link': vuln_data['bdsa_link'],
                'updatedDate': vuln_data['vuln_detail']['updatedDate']
            })

        return self.group_vulnerability_entries(vuln_list, component_files)

    def get_bom_status(self, version):
        '''Retrieve the BOM status for a project version.'''
        url = f"{version['_meta']['href']}/bom-status"
        headers = {
            'Accept': 'application/vnd.blackducksoftware.bill-of-materials-6+json'}
        result = self.hub_client.get_json(url, headers=headers)
        return result

    def get_version_journal(self, version, start_date):
        '''Retrieve journal entries from blackduck_hub updates for a project version.
           These are associated with blackduck_system user.
           We are only interested in these events:
           * Vulnerability Found:
                 New CVE found
           * Component Deleted:
                 Component is renamed.  It is usually followed by
                 "Component Added" and "Vulnerability Found".  We will close the
                 old issue and open a new one using the new name.
        '''
        date_string = start_date.isoformat()
        encoded_date_string = urllib.parse.quote(date_string)

        vuln_entries, removed_entries = [], []
        url_base = version['_meta']['href'].replace(
            'api', 'api/journal')
        url = (
            f"{url_base}?sort=timestamp%20DESC"
            f"&filter=journalTriggerNames%3Ablackduck_system"
            f"&filter=journalDate%3A%3E%3D{encoded_date_string}"
            f"&filter=journalAction%3Avulnerability_detected"
            f"&filter=journalAction%3Acomponent_deleted"
            f"&limit=1000"
        )
        headers = {
            'Accept': 'application/vnd.blackducksoftware.journal-4+json'}
        activities = self.hub_client.get_json(url, headers=headers)

        if activities.get('totalCount') == 0:
            logging.info(
                'No vulnerability updates from Black Duck Hub since the last scan.')
            return [], []

        journal_entries = activities.get('items', [])
        for entry in journal_entries:
            if entry['action'] == 'Vulnerability Found':
                vuln_id = entry['currentData']['vulnerabilityId']
                # Skip if CVE is in the exclusion list
                if vuln_id in (constants.EXCLUDED_CVE_LIST,
                               constants.EXCLUDED_BDSA_LIST):
                    logging.info(
                        f"Vulnerability {vuln_id} is on the excluded list")
                    continue

                # Process vulnerability details using helper method
                vuln_data = self._process_vulnerability_detail(vuln_id)
                if vuln_data is None or not vuln_data:
                    continue

                vuln_entries.append({
                    'componentName': entry['currentData']['projectName'],
                    'componentVersionName': entry['currentData']['releaseVersion'],
                    'severity': vuln_data['severity'],
                    'cve_id': vuln_data['cve_id'],
                    'bdsa_id': vuln_data['bdsa_id'],
                    'cve_severity': vuln_data['cve_severity'],
                    'bdsa_severity': vuln_data['bdsa_severity'],
                    'cve_link': vuln_data['cve_link'],
                    'bdsa_link': vuln_data['bdsa_link'],
                    'updatedDate': entry['timestamp']
                })
            elif entry['action'] == 'Component Deleted':
                removed_entries.append({
                    'componentName': entry['objectData']['name'],
                    'componentVersionName': entry['currentData']['version'],
                    'updatedDate': entry['timestamp']
                })

        grouped_update_entries = self.group_journal_entries(vuln_entries)

        return grouped_update_entries, removed_entries
