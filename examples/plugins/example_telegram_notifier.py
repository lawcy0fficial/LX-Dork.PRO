"""
Example notifier plugin: sends a Telegram message when a scan finds new
results. Copy this file into your plugins directory (see plugins.py's
module docstring for the resolution order -- LXDORK_PLUGINS_DIR env var,
or ~/.config/lx-dork-pro/plugins/) to use it, then run with:

    lxdorkpro preset git-exposure --target example.com --watch 30 \\
        --notifiers telegram

Configuration: add these two keys to your LX-Dork-Pro config file
(wherever `lxdorkpro configure` writes it -- run `lxdorkpro configure
--help` to check the path) or set them as environment variables if your
config.py setup supports that (see config.py for exactly how config
values are resolved in your installed version):

    telegram_bot_token = "123456:ABC-DEF..."   # from @BotFather
    telegram_chat_id = "-1001234567890"         # the chat/channel to post to

This file is a template, not auto-loaded -- LX-Dork-Pro only discovers
plugins from the plugins directory, not from examples/.
"""

import requests

from lxdorkpro.notify import BaseNotifier, NotifyError


class TelegramNotifier(BaseNotifier):
    name = "telegram"

    def notify(self, title: str, new_urls: list, job_key: str = "") -> None:
        token = self.cfg.get("telegram_bot_token")
        chat_id = self.cfg.get("telegram_chat_id")
        if not token or not chat_id:
            raise NotifyError(
                "telegram_bot_token/telegram_chat_id not configured -- "
                "see this plugin's module docstring for how to set them"
            )

        # Telegram messages have a ~4096 character limit -- show the first
        # 20 URLs and a "+N more" note rather than risking a truncated or
        # rejected message on a large batch of new results.
        shown = new_urls[:20]
        lines = [f"*{title}* -- {len(new_urls)} new result(s)"] + [f"• {u}" for u in shown]
        if len(new_urls) > len(shown):
            lines.append(f"...and {len(new_urls) - len(shown)} more")
        text = "\n".join(lines)

        try:
            resp = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
                timeout=10,
            )
        except requests.RequestException as e:
            # Don't interpolate `e`: requests includes the request URL, which contains the bot token.
            raise NotifyError(f"Telegram request failed ({type(e).__name__})") from None

        if resp.status_code >= 300:
            raise NotifyError(f"Telegram API returned {resp.status_code}: {resp.text[:200]}")
