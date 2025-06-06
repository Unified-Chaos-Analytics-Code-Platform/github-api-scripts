"""
途中まで作ったけど最終的に動かなかったので供養
"""


import json
from csv import DictWriter
from datetime import datetime, timezone
from time import sleep
from typing import Generator
from requests import exceptions, post


class PullsCollector:
    MAX_FETCH_RETRY = 3
    # Fields written to the CSV file.  The previous version of this script used
    # the pull request API and the field list no longer matched the actual
    # response from the vulnerability alerts API.  Align the field names with
    # the data returned by the GraphQL query below.
    fields = [
        "created_at",
        "package_name",
        "severity",
        "vulnerable_version_range",
    ]

    def __init__(self, token: str, repo_owner: str, repo_name: str):
        self._repo_owner = repo_owner
        self._repo_name = repo_name
        self._headers = {"Authorization": f"token {token}"}
        self.cursor = None

    def save_all(self, output_path: str):
        with open(output_path, 'w', encoding='utf-8', buffering=1) as f:
            writer = DictWriter(f, self.fields)
            writer.writeheader()
            for row in self.all():
                writer.writerow(row)
            print("\nFinish to collect the vulnerability list. Output is " + output_path)

    def all(self) -> Generator:
        self.cursor = None
        gene = self._generator()
        hasNextPage = True
        while hasNextPage:
            obj = next(gene)
            if "errors" in obj:
              continue

            for alert in (edge['node'] for edge in obj['data']['repository']['vulnerabilityAlerts']['edges']):
                yield self._format(alert)
            hasNextPage = obj['data']['repository']['vulnerabilityAlerts']['pageInfo']['hasNextPage']
            self.cursor = obj['data']['repository']['vulnerabilityAlerts']['pageInfo']['endCursor']
            if obj['data']['rateLimit']['remaining'] < 1:
                reset_at = self._parse_datetime(obj['data']['rateLimit']['resetAt'])
                delta = reset_at - datetime.now(timezone.utc)
                sleep(delta.seconds)

    def _generator(self):
        nth_retry = 0
        while(True):
            try:
              res = post(
                    'https://api.github.com/graphql',
                    headers=self._headers,
                    data=self._graphql_request(),
                ).json()
              if "errors" in res:
                if nth_retry < self.MAX_FETCH_RETRY:
                  nth_retry += 1
                  # Magic number to avoid timeout
                  sleep(10)
                  continue
                else:
                  nth_retry = 0
                  print(res["errors"])
              yield res
            except exceptions.HTTPError as http_err:
                raise http_err
            except Exception as err:
                raise err

    def _graphql_request(self) -> str:
        """GitHub GraphQL Query

        See https://developer.github.com/v4/object/pullrequest/
        """
        query = '''
            query($cursor: String) {
              rateLimit {
                remaining
                resetAt
              }
              repository(owner: "%(repo_owner)s", name: "%(repo_name)s") {
                vulnerabilityAlerts(after: $cursor, first: 50) {
                  pageInfo {
                    hasNextPage
                    endCursor
                  }
                  edges {
                    node {
                      createdAt
                      securityVulnerability {
                        package {
                          name
                        }
                        severity
                        vulnerableVersionRange
                      }
                    }
                  }
                }
              }
            }
        ''' % {'repo_owner': self._repo_owner, 'repo_name': self._repo_name}
        # return query
        return json.dumps({'query': query, 'variables': {'cursor': self.cursor}}).encode('utf-8')

    def _format(self, vuln: dict) -> dict:
        """Convert a vulnerability alert node to a flat dictionary.

        The previous implementation expected pull request fields and raised
        ``KeyError`` for the actual vulnerability alert response.  Each alert
        contains ``createdAt`` and a ``securityVulnerability`` object with the
        affected package, the severity and the vulnerable version range.
        """

        sec = vuln["securityVulnerability"]
        return {
            "created_at": self._parse_datetime(vuln["createdAt"]),
            "package_name": sec["package"]["name"],
            "severity": sec["severity"],
            "vulnerable_version_range": sec["vulnerableVersionRange"],
        }

    def _parse_datetime(self, d: str) -> datetime:
        """Return a timezone-aware datetime parsed from an ISO 8601 string."""
        return datetime.strptime(d, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


if __name__ == "__main__":
    import os

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise SystemExit("Set the GITHUB_TOKEN environment variable")

    collector = PullsCollector(token, "kubernetes", "kubernetes")
    for alert in collector.all():
        print(alert)
