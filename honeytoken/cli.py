"""honeytoken-sentinel CLI.

Examples:
    honeytoken mint aws --hint "~/.aws/credentials on staging-box"
    honeytoken mint url --base https://canary.example.com
    honeytoken list
    honeytoken scan logs/*.log
    honeytoken serve --port 8080
"""
from __future__ import annotations
import argparse
import json
import logging
import sys
from pathlib import Path

from . import tokens
from .registry import Registry
from .listener import run_listener, make_slack_webhook


DEFAULT_REGISTRY = "honeytokens.json"


def cmd_mint(args: argparse.Namespace) -> int:
    reg = Registry(args.registry)
    kind = args.kind
    if kind == "aws":
        tk = tokens.mint_aws_key(placement_hint=args.hint or "~/.aws/credentials")
    elif kind == "github":
        tk = tokens.mint_github_pat(placement_hint=args.hint or "scripts/deploy.sh")
    elif kind == "stripe":
        tk = tokens.mint_stripe_key(placement_hint=args.hint or ".env")
    elif kind == "url":
        if not args.base:
            print("--base is required for url tokens", file=sys.stderr)
            return 2
        tk = tokens.mint_canary_url(base_url=args.base, placement_hint=args.hint or "internal wiki")
    elif kind == "doc":
        tk = tokens.mint_decoy_doc(filename=args.filename or "FINANCIALS.xlsx",
                                   placement_hint=args.hint or "shared drive")
    else:
        print(f"unknown token kind: {kind}", file=sys.stderr)
        return 2
    reg.add_token(tk)
    print(json.dumps(tk.to_dict(), indent=2))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    reg = Registry(args.registry)
    if args.json:
        out = [t.to_dict() for t in reg.tokens]
        print(json.dumps(out, indent=2))
        return 0
    if not reg.tokens:
        print("(no honeytokens minted yet)")
        return 0
    for t in reg.tokens:
        triggers = len(reg.events_for(t.token_id))
        print(f"{t.token_id}\t{t.kind:11}\t{t.created_at}\ttriggers={triggers}\t{t.placement_hint}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan files (logs, commits, etc.) for any minted token."""
    reg = Registry(args.registry)
    hits_total = 0
    for path_str in args.files:
        path = Path(path_str)
        if not path.exists():
            print(f"skip: {path} (not found)", file=sys.stderr)
            continue
        try:
            text = path.read_text(errors="ignore")
        except Exception as e:
            print(f"skip: {path} ({e})", file=sys.stderr)
            continue
        hits = tokens.detect_in_text(text, reg.tokens)
        for h in hits:
            hits_total += 1
            print(f"[HIT] {path} contains {h.token_id} ({h.kind})")
    print(f"\nscanned {len(args.files)} file(s), {hits_total} hit(s)", file=sys.stderr)
    return 0 if hits_total == 0 else 1


def cmd_events(args: argparse.Namespace) -> int:
    reg = Registry(args.registry)
    events = reg.events
    if args.token:
        events = [e for e in events if e.token_id == args.token]
    for e in events:
        ip = e.source_ip or "?"
        ua = (e.user_agent or "?")[:80]
        print(f"{e.timestamp}\t{e.token_id}\t{ip}\t{ua}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    webhook = make_slack_webhook(args.slack_webhook) if args.slack_webhook else None
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    run_listener(args.registry, port=args.port, webhook=webhook)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="honeytoken", description="mint decoy creds, alert on access")
    p.add_argument("--registry", default=DEFAULT_REGISTRY, help="path to JSON registry file")
    sp = p.add_subparsers(dest="cmd", required=True)

    pm = sp.add_parser("mint", help="mint a new honeytoken")
    pm.add_argument("kind", choices=["aws", "github", "stripe", "url", "doc"])
    pm.add_argument("--hint", help="where to place this token (free-text)")
    pm.add_argument("--base", help="canary listener base URL (for kind=url)")
    pm.add_argument("--filename", help="decoy filename (for kind=doc)")
    pm.set_defaults(func=cmd_mint)

    pl = sp.add_parser("list", help="list minted tokens")
    pl.add_argument("--json", action="store_true")
    pl.set_defaults(func=cmd_list)

    ps = sp.add_parser("scan", help="scan files for any minted token")
    ps.add_argument("files", nargs="+")
    ps.set_defaults(func=cmd_scan)

    pe = sp.add_parser("events", help="show trigger events")
    pe.add_argument("--token", help="filter by token_id")
    pe.set_defaults(func=cmd_events)

    psv = sp.add_parser("serve", help="run the canary HTTP listener")
    psv.add_argument("--port", type=int, default=8080)
    psv.add_argument("--slack-webhook", help="post hits to this Slack webhook")
    psv.set_defaults(func=cmd_serve)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
