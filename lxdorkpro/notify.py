"""
Webhook notifications: alert Slack, Discord, or any generic JSON webhook
when a scan finds new results -- most useful with --watch, so you don't
have to stay staring at a terminal to know something new showed up.

Also defines BaseNotifier, the plugin interface for notification channels
this module doesn't build in (Telegram, PagerDuty, email, ...) -- see
plugins.py for how a dropped-in BaseNotifier subclass gets discovered and
registered, the same mechanism BaseEngine plugins already use.
"""

from typing import List, Optional, Type
import time

import requests

from .engines import MAX_RETRY_WAIT, _parse_retry_after, SearchResult


class NotifyError(Exception):
    """Raised when a webhook delivery fails outright (network/HTTP error).
    Notification failures are reported but never abort a scan.
    """


class BaseNotifier:
    """Plugin interface for a notification channel. Subclass this, set
    `.name`, implement `.notify()`, and drop the file in the plugins
    directory (see plugins.py's module docstring for the exact location)
    to make it available via `--notifiers <name>`.

    `__init__` receives the full loaded config dict, mirroring
    engines.BaseEngine's constructor -- a notifier reads whatever custom
    keys it needs from `self.cfg` itself (e.g. a Telegram plugin might
    read `cfg.get("telegram_bot_token")`), the same way a paid-API search
    engine reads its own API key. This keeps config.py from needing to
    know about every possible plugin's specific settings in advance.

    `notify()` should raise NotifyError on failure (network/auth/etc) --
    callers catch that and warn rather than let a failed notification
    abort a scan, exactly like the built-in webhook path below.
    """
    name = "base"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def notify(self, title: str, new_urls: List[str], job_key: str = "") -> None:
        raise NotImplementedError


# Populated by plugins.install_plugins_into_registry() at CLI startup;
# empty by default since Slack/Discord/generic webhooks (below) are
# built in and don't need to be registered here. Keyed by `.name`.
NOTIFIER_REGISTRY: dict = {}


DISCORD_LIMIT = 2000


def _fit_discord(content: str) -> str:
    """Discord rejects (HTTP 400) a message over 2000 chars -- which 20 long
    URLs can exceed -- and the alert would be lost. Trim at a line boundary."""
    if len(content) <= DISCORD_LIMIT:
        return content
    cut = content[: DISCORD_LIMIT - 40].rsplit("\n", 1)[0]
    return cut + "\n… (truncated; more results than fit)"


def _slack_escape(text: str) -> str:
    # Slack mrkdwn treats & < > specially (<!channel> etc.); URLs come from untrusted search results.
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _build_slack_payload(title: str, new_urls: List[str], job_key: str) -> dict:
    lines = "\n".join(f"• {_slack_escape(u)}" for u in new_urls[:20])
    if len(new_urls) > 20:
        lines += f"\n… and {len(new_urls) - 20} more"
    return {
        "text": f":mag: *LX-Dork-Pro* found {len(new_urls)} new result(s) for `{_slack_escape(title)}`\n{lines}",
    }


def _build_discord_payload(title: str, new_urls: List[str], job_key: str) -> dict:
    lines = "\n".join(f"• {u}" for u in new_urls[:20])
    if len(new_urls) > 20:
        lines += f"\n… and {len(new_urls) - 20} more"
    return {
        "content": f"🔍 **LX-Dork-Pro** found {len(new_urls)} new result(s) for `{title}`\n{lines}",
        "allowed_mentions": {"parse": []},  # a URL containing @everyone must not ping the channel
    }


def _build_generic_payload(title: str, new_urls: List[str], job_key: str) -> dict:
    return {
        "tool": "lx-dork-pro",
        "job": title,
        "job_key": job_key,
        "new_result_count": len(new_urls),
        "new_urls": new_urls,
    }


_PAYLOAD_BUILDERS = {
    "slack": _build_slack_payload,
    "discord": _build_discord_payload,
    "generic": _build_generic_payload,
}


def detect_webhook_kind(url: str) -> str:
    if "hooks.slack.com" in url:
        return "slack"
    if "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url:
        return "discord"
    return "generic"


def send_notification(
    webhook_url: str, title: str, new_urls: List[str], job_key: str = "",
    kind: Optional[str] = None, timeout: float = 10.0,
    max_attempts: int = 3, sleep=None,
) -> None:
    """Send a new-results notification to a Slack/Discord/generic webhook.
    `kind` is auto-detected from the URL if not given. Raises NotifyError
    on failure -- callers should catch this and warn rather than crash the
    scan over a failed notification.
    """
    if not new_urls:
        return  # nothing new -- don't spam the webhook every watch cycle

    kind = kind or detect_webhook_kind(webhook_url)
    builder = _PAYLOAD_BUILDERS.get(kind, _build_generic_payload)
    payload = builder(title, new_urls, job_key)
    if kind == "discord":
        payload["content"] = _fit_discord(payload["content"])

    # Retry transient failures (network errors, 429, 5xx) with backoff, honouring
    # Retry-After up to a ceiling. A dropped alert in an unattended --watch run
    # is a missed finding, so one blip shouldn't lose it. Client errors (4xx
    # other than 429: bad URL, revoked webhook) fail immediately.
    sleep = sleep or time.sleep  # resolved at call time so tests/callers can substitute it
    last_error = "unknown error"
    for attempt in range(max(1, max_attempts)):
        retry_wait = None
        try:
            resp = requests.post(webhook_url, json=payload, timeout=timeout)
        except requests.RequestException as e:
            # NEVER interpolate `e`: requests embeds the request URL in its
            # message, and a Slack/Discord webhook URL is itself the credential.
            last_error = f"Webhook delivery failed ({type(e).__name__})"
        else:
            if resp.status_code < 300:
                return
            last_error = f"Webhook returned HTTP {resp.status_code}: {resp.text[:200]}"
            if resp.status_code != 429 and resp.status_code < 500:
                raise NotifyError(last_error)
            retry_wait = _parse_retry_after(resp.headers.get("Retry-After")) if resp.status_code == 429 else None
        if attempt < max_attempts - 1:
            wait = retry_wait if retry_wait is not None else 1.5 * (2 ** attempt)
            sleep(min(max(wait, 0.0), MAX_RETRY_WAIT))
    raise NotifyError(last_error)


def notify_new_results(
    webhook_url: str, title: str, new_urls_set, job_key: str = "", kind: Optional[str] = None
) -> Optional[str]:
    """Convenience wrapper: takes the `new_urls` set from history.diff_against_last
    directly. Returns an error message string on failure (never raises) so
    callers can just check truthiness and print a warning.
    """
    try:
        send_notification(webhook_url, title, sorted(new_urls_set), job_key, kind)
        return None
    except NotifyError as e:
        return str(e)


def notify_via_plugin(name: str, cfg: dict, title: str, new_urls_set, job_key: str = "") -> Optional[str]:
    """Dispatch a new-results notification through a registered
    BaseNotifier plugin by name, mirroring notify_new_results's
    never-raise convention (returns an error message string on failure,
    None on success or when there's nothing new to report).

    Unlike the webhook path, this doesn't take a URL -- the plugin reads
    whatever endpoint/token/routing-key it needs out of `cfg` itself (see
    BaseNotifier's docstring), since different notifier plugins need
    entirely different configuration shapes that a single `--webhook`-style
    flag can't express.
    """
    new_urls = sorted(new_urls_set)
    if not new_urls:
        return None  # nothing new -- don't spam the channel every watch cycle

    notifier_cls = NOTIFIER_REGISTRY.get(name)
    if notifier_cls is None:
        return f"No notifier plugin named '{name}' is registered. Run `lxdorkpro plugins` to see what's loaded."

    try:
        notifier = notifier_cls(cfg)
        notifier.notify(title, new_urls, job_key)
        return None
    except NotifyError as e:
        return str(e)
    except Exception as e:  # noqa: BLE001 -- a broken plugin must not crash the scan
        return f"Notifier plugin '{name}' raised an unexpected error: {type(e).__name__}: {e}"
