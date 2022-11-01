#!/usr/bin/env python3

import re
import argparse
from datetime import datetime
import json
import logging
import sys
import timestring
from itertools import groupby

from blackduck.HubRestApi import HubInstance

from jira_rest_api import JiraRestApi

import config
from components import COMPONENTS

from blackduck_rest_api import Blackduck

logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', stream=sys.stderr, level=logging.INFO)

def datetime_format(dt):
    return "%s:%.3f%s" % (
        dt.strftime('%Y-%m-%dT%H:%M'),
        float("%.3f" % (dt.second + dt.microsecond / 1e6)),
        dt.strftime('%z')
    )

# Create a list of notifications based on notification type
# To-Do: do we want to further filter project version here?
#        i.e. affectedProjectVersions could have 7.1.0, 7.0.4, 7.0.3
#             if we only want 7.1.0
def get_notification_info(notification, notification_type):
    n = []
    for affected_version in notification['content']['affectedProjectVersions']:
        n.append({'component_name': notification['content']['componentName'],
                              'version': notification['content']['versionName'],
                              'version_url': notification['content']['componentVersion'],
                              'cves_list': [v['vulnerabilityId'] for v in notification['content'][notification_type]],
                              'project_name': affected_version['projectName'],
                              'project_version': affected_version['projectVersionName'],
                              'project_version_url': affected_version['projectVersion'],
                              'notification_type': notification_type,
                              'date': notification['createdAt'].replace('Z', '-0800')
        })
    return n

# Associated impacted files, cve links, severity, etc. with notifications to create potential jira entries
def jira_entries(notifications, cve_dicts):
    for n in range(len(notifications)):
        notifications[n]['cb_component'] = 'Unknown'
        if notifications[n]['project_name'] in COMPONENTS:
            for key, value in COMPONENTS[notifications[n]['project_name']].items():
                if any(v in notifications[n]['component_name'].lower() for v in value):
                    notifications[n]['cb_component'] = key
                    break
        cves = []
        for v in notifications[n]['cves_list']:
            cve = {}
            cve['name'] = cve_dicts[v]['name']
            cve['severity'] = cve_dicts[v]['severity']
            for l in cve_dicts[v]['_meta']['links']:
                if l['rel'] == 'nist':
                    cve['link']=l['href']
                    break
            cves += [cve]
        project_version = notifications[n]['project_version']
        component_version_url = notifications[n]['version_url']
        if project_version not in project_files.keys():
            project_files[notifications[n]['project_version']] = blackduck.get_project_version_files(notifications[n]['project_version_url'])
        notifications[n]['files'] = project_files[project_version][component_version_url]

        # Sort each notification's CVEs in the order of severities.  The first one is the highest should represent
        # the severity of the component
        cves.sort(key = lambda d: config.BLACKDUCK['severity_list'].index(d['severity']))
        notifications[n]['cves'] = cves
        notifications[n]['severity'] = cves[0]['severity']
    return notifications

# Open a jira issue
# There are two possibilities:
#   - Create a brand new ticket.
#   - Reopen an existing ticket.  The ticket was closed when CVEs were cleared.  Now, new CVEs have been identified.

def open_jira_issue(jira, notification, issue=None):
    detail_cves = ''
    detail_files = '\n'.join(notification['files'])
    for cve in notification['cves']:
        detail_cves += f"{cve['severity']}:[ [{cve['name']}|{cve['link']}] ]\n"

    notification['summary'] = (f"{notification['project_name']}:{notification['project_version']},"
                               f"{notification['component_name']}:{notification['version']}")
    notification['detail'] = (f"*Project*:{notification['project_name']}\n"
                              f"*Project Version*:{notification['project_version']}\n"
                              f"---------------------------------------\n"
                              f"*Component*:*{notification['component_name']}*\n"
                              f"*Component Version*:{notification['version']}\n"
                              f"*Severity Status*:*{notification['severity']}*\n"
                              f"---------------------------------------\n*Current Vulnerabilities*:\n"
                              f"{{anchor}}\n"
                              f"{detail_cves}"
                              f"{{anchor}}\n"
                              f"\n---------------------------------------\n*Files*:\n"
                              f"{detail_files}")

    if issue is None:
        related_issues = jira.search_issues(config.JIRA['project'],
                              notification['component_name'],
                              notification['version'],
                              notification['project_name'],
                             )
        new_issue = jira.new_issue(config.JIRA['project'], notification)
        logging.info('Creating a new Jira issue, %s', new_issue.key)
        # When severity is LOW, we want to keep a record of it, but leave it in 'Not Applicable' State
        if notification['severity'] == 'LOW':
            jira.transition_issue(new_issue, config.JIRA['not_applicable'], notification['date'])

        if related_issues:
            for r in related_issues:
                jira.create_issue_link(new_issue.key, r.key)
    else:
        logging.info('Checking %s to see if it needs to be re-opened.', issue.key)
        # Use update_jira_issue to check if any field is changed and reopen ticket as needed.
        if not ((issue.fields.status.name == 'Component Not Applicable') or (notification['severity'] == 'LOW')):
            update_jira_issue(jira, notification, issue)

# Close a jira ticket
def close_jira_issue(jira, notification, issue):
    logging.info('Checking to see if %s needs to be closed.', issue.key)
    # Let's make sure we don't process an older scan.
    #if getattr(issue.fields, config.JIRA['BD_LAST_UPDATE']) > notification['date']:
        #logging.info('%s BD_LAST_UPDATE is newer than %s, skipped', issue.key, notification['date'])
    #elif issue.fields.status.name not in ['Done', 'Not Applicable', 'Mitigated', 'Component Not Applicable']:
        #jira.transition_issue(issue, config.JIRA['done'], notification['date']) #transition to DONE

def update_ticket_fields (notification, ticket_cves_list, ticket_cves, detail_sum, detail_files):
    ticket_detail_cves = ''
    ticket_fields = {}
    ticket_fields['date'] = notification['date']
    ticket_fields['cves_list'] = ticket_cves_list
    ticket_cves.sort(key = lambda d: config.BLACKDUCK['severity_list'].index(d['severity']))
    ticket_fields['severity'] = ticket_cves[0]['severity']
    for t_cve in ticket_cves:
        ticket_detail_cves += f"{t_cve['severity']}:[ [{t_cve['name']}|{t_cve['link']}] ]\n"

    for file in notification['files']:
        if not re.search(file, detail_files):
            detail_files += f"{file}\n"

    ticket_fields['detail'] = (f"{detail_sum}"
                               f"{{anchor}}\n"
                               f"{ticket_detail_cves}"
                               f"{{anchor}}"
                               f"{detail_files}")
    return ticket_fields

def update_jira_issue(jira, notification, issue):
    ticket_cves = []
    ticket_needs_update = False

    logging.info('Checking to see if %s needs to be updated.', issue.key)
    # notification['date'] is older than the ticket's BD_LAST_UPDATE
    # The notificaiton was likely processed before.  We don't want to process again.
    if getattr(issue.fields, config.JIRA['BD_LAST_UPDATE']) > notification['date']:
        logging.info("%s BD_LAST_UPDATE %s is newer than %s. Skipped.", issue.key, getattr(issue.fields, config.JIRA['BD_LAST_UPDATE']), notification['date'])
        return
    # Get existing ticket data
    ticket_cves_list = list(getattr(issue.fields, config.JIRA['BD_CVES']).split(','))
    ticket_severity = getattr(issue.fields, config.JIRA['BD_SEVERITY'])
    [detail_sum, detail_cves, detail_files]  = re.split('{anchor}', getattr(issue.fields, config.JIRA['BD_DETAIL']))
    lines = [s for s in detail_cves.splitlines() if s]
    for line in lines:
        [severity, name, url, junk] = re.split(r':\[ \[|\||\] \]', line)
        ticket_cves.append({'severity': severity, 'name': name, 'link': url})

    if notification['notification_type'] == 'newVulnerabilityIds':
        for n in notification['cves']:
            if n['name'] not in ticket_cves_list:
                ticket_needs_update = True
                ticket_cves_list.append(n['name'])
                ticket_cves.append({'severity': n['severity'],
                                    'name': n['name'],
                                    'link': n['link']})
        if ticket_needs_update:
            ticket_fields=update_ticket_fields (notification, ticket_cves_list, ticket_cves, detail_sum, detail_files)
    if notification['notification_type'] == 'deletedVulnerabilityIds':
        #if issue is already in Done state, no need to process
        if issue.fields.status.name not in ['Done', 'Not Applicable', 'Mitigated', 'Component Not Applicable']:
            for n in notification['cves']:
                if n['name'] in ticket_cves_list:
                    ticket_needs_update = True
                    ticket_cves_list.remove(n['name'])
                    for t_cve in ticket_cves.copy():
                        if n['name'] == t_cve['name']:
                            ticket_cves.remove(t_cve)

            if not ticket_cves_list:
                jira.transition_issue(issue, config.JIRA['done'], notification['date']) #transition to DONE
                return
            else:
                ticket_fields=update_ticket_fields (notification, ticket_cves_list, ticket_cves, detail_sum, detail_files)

    if notification['notification_type'] == 'updatedVulnerabilityIds':
        ticket_needs_update = True
        for n in notification['cves']:
            if not any(t.get('name') == n['name'] for t in ticket_cves):
                ticket_cves.append({'severity': n['severity'], \
                                    'name': n['name'], \
                                    'link': n['link']})
        ticket_fields=update_ticket_fields (notification, ticket_cves_list, ticket_cves, detail_sum, detail_files)

    if ticket_needs_update :
        jira.update_issue(issue, ticket_fields)
        if issue.fields.status.name in ['Done', 'Not Applicable', 'Mitigated']:
            if notification['severity'] != 'LOW':
                jira.transition_issue(issue, config.JIRA['to_do'], notification['date']) #transition to TO DO

parser = argparse.ArgumentParser('Retreive vulnerability notifications')
parser.add_argument('-p', '--project_name', required=True, help='Search notifications for this project.')
parser.add_argument('-v', '--version_name', help='Filter notifications for specific version.')
parser.add_argument('-n', '--newer_than',
                    default=None,
                    type=str,
                    help='Filter notifications by date/time.')
parser.add_argument('-o', '--older_than',
                    default=None,
                    type=str,
                    help='Filter notifications by date/time.')
args = parser.parse_args()

if args.newer_than:
    newer_than = timestring.Date(args.newer_than).date
else:
    newer_than = None

if args.older_than:
    older_than = timestring.Date(args.older_than).date
else:
    older_than = None

if args.version_name:
    version_name = args.version_name
else:
    version_name = None

blackduck = Blackduck()
notifications =  blackduck.get_vulnerability_notifications(args.project_name, version_name, newer_than, older_than)
scan_notifications = []
update_notifications = []
all_cves_list = []
cve_dicts = {}
project_files = {}

# Keep two lists of notifications: scan and update
# Blackduck notifications can be categorized based on vulnerabilityNotificationCause and eventSource.  Common entries include:
#   - eventSource: SCAN, KB_UPDATE, USER_ACTION, USER_ACTION_REMEDIATION, USER_ACTION_REPRIORITIZATION
#   - vulnerabilityNotificationCause: ADDED, REMOVED, IGNORE_CHANGED, SEVERITY_CHANGED
# eventsource SCAN gives us 90% of notifications from scans.  A scan also triggers eventSource=USER_ACTION +
# vulnerabilityNotificationCause=Removed.  It is unclear the logic behind it.
#
# Keep two lists of notifications to process: scan and update
#   - Scan: Since we do fresh scans, all vulnerabilities are removed and re-added for each scan.  This could lead to one of these scenarios:
# a new ticket if it doesn't exist, re-opening of a closed ticket, or closing  a ticket.  No need to worry about modifying a ticket.
#
#   - Update: notifications from eventSource of KB_UPDATE, USER_ACTION_REMEDIATION, etc.  These are not done by scan.
# These could lead to a new ticket, add/update/remove vulnerabilities to an existing ticket, transition a ticket.
for notification in notifications:
    if notification['content']['eventSource'] == 'SCAN':
        if notification['content']['newVulnerabilityIds']:
            scan_notifications += get_notification_info(notification, 'newVulnerabilityIds')
        if notification['content']['deletedVulnerabilityIds']:
            scan_notifications += get_notification_info(notification, 'deletedVulnerabilityIds')
    elif notification['content']['vulnerabilityNotificationCause'] == 'REMOVED' and notification['content']['eventSource'] == 'USER_ACTION':
        if notification['content']['deletedVulnerabilityIds']:
            scan_notifications += get_notification_info(notification, 'deletedVulnerabilityIds')
    elif notification['content']['vulnerabilityNotificationCause'] != 'SEVERITY_CHANGED':
        if notification['content']['newVulnerabilityIds']:
            update_notifications += get_notification_info(notification, 'newVulnerabilityIds')
        if notification['content']['deletedVulnerabilityIds']:
            update_notifications += get_notification_info(notification, 'deletedVulnerabilityIds')
        if notification['content']['updatedVulnerabilityIds']:
            update_notifications += get_notification_info(notification, 'updatedVulnerabilityIds')

# There are a lot of duplicates in the scan notifications since we do fresh scan every time.  Same vulnerabilities are removed and added
# repeatedly.  It is safe to ignore the older duplicates and to focus on the latest.  First, sort the notifications by component, version,
# add/remove, and date.  Then, use groupby to keep the latest unique entry on the list

scan_notifications.sort(key = lambda x: (x['component_name'], x['version'], x['notification_type'], x['date']))
unique_scan_notifications = [max(g, key=lambda j: j['date']) for k,g in groupby(scan_notifications , key=lambda x: (x['component_name'], x['version']))]
# Update_notifications might only make partial change the component's CVEs; thus treating each as an unique.
# Usually, there are not a lot of updates.

update_notifications.sort(key = lambda x: (x['date']))

for n in unique_scan_notifications:
    all_cves_list.extend(n['cves_list'])
for n in update_notifications:
    all_cves_list.extend(n['cves_list'])

cve_dicts=blackduck.create_cve_dicts(list(set(all_cves_list)))

scan_notification_jira_entries = jira_entries(unique_scan_notifications, cve_dicts)
update_notification_jira_entries = jira_entries(update_notifications, cve_dicts)

jira=JiraRestApi()
for entry in scan_notification_jira_entries:
    issues = jira.search_issues(config.JIRA['project'],
                              entry['component_name'],
                              entry['version'],
                              entry['project_name'],
                              entry['project_version']
                             )
    if len(issues) > 1:
        logging.error('More than one issue is found:')
        for issue in issues:
            logging.error(issue.key)
    else:
        issue=next(issues, None)
        if entry['notification_type'] == 'newVulnerabilityIds':
            #open_jira_issue(jira, entry, issue)
            print("try to open a new issue or reopen an existing issue", entry['component_name'])
        if issue and entry['notification_type'] == 'deletedVulnerabilityIds':
            print("close an issue", entry['component_name'])
            close_jira_issue(jira, entry, issue)
