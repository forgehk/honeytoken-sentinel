"""HTTP listener — when a canary URL is fetched, we record the trigger
and (optionally) ping a webhook.

Uses only stdlib so this runs anywhere with python3, no Flask required.
"""
from __future__ import annotations
import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError

from .registry import Registry, TriggerEvent

log = logging.getLogger("honeytoken")


# Tiny transparent 1x1 GIF — returned for canary URLs so the fetcher
# (e.g. an email client previewing a link) gets a sensible response.
PIXEL_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00"
    b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
    b"\x00\x00\x02\x02D\x01\x00;"
)


class HoneyHandler(BaseHTTPRequestHandler):
    """Path conventions:
        /c/<token_id>      → canary hit, log + 200 transparent pixel
        /health            → 200 ok
        anything else      → 404
    """
    registry: Registry = None  # set by run_listener
    webhook: Optional[Callable[[TriggerEvent], None]] = None

    def log_message(self, format, *args):  # quiet stdlib chattiness
        log.debug("%s - %s", self.address_string(), format % args)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok\n")
            return

        if parsed.path.startswith("/c/"):
            tid = parsed.path[len("/c/"):].split("/")[0]
            try:
                evt = self.registry.record_trigger(
                    token_id=tid,
                    source_ip=self.client_address[0],
                    user_agent=self.headers.get("User-Agent"),
                    note="http GET",
                    extra={"path": self.path, "headers": dict(self.headers.items())},
                )
                log.warning("HONEYTOKEN TRIPPED %s from %s", tid, self.client_address[0])
                if self.webhook:
                    try:
                        self.webhook(evt)
                    except Exception as e:  # never let the webhook break the response
                        log.error("webhook failed: %s", e)
            except KeyError:
                log.info("unknown token %s from %s", tid, self.client_address[0])
            # return a tiny pixel either way — don't tip our hand
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.send_header("Content-Length", str(len(PIXEL_GIF)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(PIXEL_GIF)
            return

        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"not found\n")


def make_slack_webhook(slack_url: str) -> Callable[[TriggerEvent], None]:
    """Return a webhook callable that posts to a Slack-incoming-webhook URL.
    Failures are swallowed and logged."""
    def _send(evt: TriggerEvent) -> None:
        body = json.dumps({
            "text": (
                f":rotating_light: Honeytoken `{evt.token_id}` was triggered\n"
                f"• at {evt.timestamp}\n"
                f"• from `{evt.source_ip}`\n"
                f"• ua: `{(evt.user_agent or '?')[:120]}`"
            )
        }).encode()
        req = Request(slack_url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=5):
                pass
        except URLError as e:
            log.error("slack webhook failed: %s", e)
    return _send


def build_server(registry_path: str, port: int, webhook=None) -> HTTPServer:
    HoneyHandler.registry = Registry(registry_path)
    HoneyHandler.webhook = webhook
    return HTTPServer(("0.0.0.0", port), HoneyHandler)


def run_listener(registry_path: str, port: int = 8080, webhook=None) -> None:
    srv = build_server(registry_path, port, webhook=webhook)
    log.info("honeytoken listener bound to :%d (registry=%s)", port, registry_path)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
        srv.server_close()
