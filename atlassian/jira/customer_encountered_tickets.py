from jira_issue_manager import JiraIssueManager

JIRA_PROJECTS = {
    'MB': {
        'VERSIONS': ['7.2']
    }
}
ISSUE_IMPACT_FIELD_ID = '12659'
SET_ISSUE_IMPACT_FIELD_EXTERNAL = {
    f'customfield_{ISSUE_IMPACT_FIELD_ID}': {
        "value": "external"
    }
}


def find_tickets_with_linked_cbse(jira_session, project_key, affected_version):
    '''
        Find tickets of given version:
            - type of Bug, Task, and Improvement
            - has a linked issue associated with CBSE project
            - the linked issue must be Task or Bug
        Return a list of issue keys
    '''
    # Double quotes in JQL are used to deal with spaces and special characters
    search_str = (
        f'project={project_key} AND '
        f'issuetype in (Bug, Task, Improvement) AND '
        f'(affectedVersion ~ "{affected_version}" OR affectedVersion ~ "{affected_version}.*") AND '
        f'cf[{ISSUE_IMPACT_FIELD_ID}] is EMPTY AND '
        f'issueLinkType is not EMPTY'
    )
    issues = []
    issues_with_cbse = []
    start_at = 0
    batch_size = 100
    while True:
        batch = jira_session.client.search_issues(
            search_str,
            startAt=start_at,
            maxResults=batch_size,
            # Only get the fields we need
            fields='key,versions,issuelinks',
            json_result=True
        )
        if not batch:
            break

        issues.extend(batch['issues'])
        if start_at + batch_size >= batch['total']:
            break
        start_at += batch_size

    for issue in issues:
        # Process issue links
        for link in issue['fields']['issuelinks']:
            linked_issue = link.get('outwardIssue') or link.get('inwardIssue')
            if (linked_issue and 'cbse' in linked_issue['key'].lower(
            ) and linked_issue['fields']['issuetype']['name'] in ['Bug', 'Task']):
                issues_with_cbse.append(issue['key'])
                break
    return issues_with_cbse


session = JiraIssueManager()
for project in JIRA_PROJECTS:
    for version in JIRA_PROJECTS[project]['VERSIONS']:
        issues = find_tickets_with_linked_cbse(
            session,
            project,
            version
        )
        for issue in issues:
            session.update_issue(issue, SET_ISSUE_IMPACT_FIELD_EXTERNAL)
