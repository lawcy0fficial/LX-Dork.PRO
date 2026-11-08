"""
Example exporter plugin: creates a Jira issue summarizing a scan's
results, instead of (or alongside) writing a local file with --output.
Copy this file into your plugins directory (see plugins.py's module
docstring for the resolution order) to use it, then run with:

    lxdorkpro preset git-exposure --target example.com --export-via jira

Configuration: add these keys to your LX-Dork-Pro config (see config.py
for exactly how config values are resolved in your installed version):

    jira_base_url = "https://your-org.atlassian.net"
    jira_email = "you@your-org.com"
    jira_api_token = "..."          # https://id.atlassian.com/manage-profile/security/api-tokens
    jira_project_key = "SEC"

This file is a template, not auto-loaded -- LX-Dork-Pro only discovers
plugins from the plugins directory, not from examples/.
"""

import requests

from lxdorkpro.exporter import BaseExporter


class JiraExporter(BaseExporter):
    name = "jira"

    def export(self, results: list, title: str = "LX-Dork-Pro Results") -> str:
        base_url = self.cfg.get("jira_base_url")
        email = self.cfg.get("jira_email")
        token = self.cfg.get("jira_api_token")
        project_key = self.cfg.get("jira_project_key")
        if not all([base_url, email, token, project_key]):
            raise RuntimeError(
                "jira_base_url/jira_email/jira_api_token/jira_project_key not fully "
                "configured -- see this plugin's module docstring for how to set them"
            )

        # Cap the URL list in the ticket body the same way the Telegram
        # example caps its message -- a ticket with 500 bullet points is
        # unreadable and not what anyone reviewing it actually wants; the
        # ticket points at the real report (--report-md/--report-html)
        # for the full list.
        shown = results[:30]
        lines = [f"LX-Dork-Pro found {len(results)} result(s) for: {title}", ""]
        lines += [f"- {r.url}" for r in shown]
        if len(results) > len(shown):
            lines.append(f"...and {len(results) - len(shown)} more (see the full report)")

        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[LX-Dork-Pro] {title} -- {len(results)} result(s)",
                "description": "\n".join(lines),
                "issuetype": {"name": "Task"},
            }
        }

        resp = requests.post(
            f"{base_url.rstrip('/')}/rest/api/2/issue",
            json=payload, auth=(email, token), timeout=15,
        )
        if resp.status_code >= 300:
            raise RuntimeError(f"Jira API returned {resp.status_code}: {resp.text[:300]}")

        issue_key = resp.json().get("key", "?")
        return f"{base_url.rstrip('/')}/browse/{issue_key}"
