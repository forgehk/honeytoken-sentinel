# Quickstart

A 5-minute walkthrough — mint a token, plant it, watch it fire.

## 1. Start the listener

```bash
honeytoken serve --port 8080
```

In production, put this behind nginx/Caddy with TLS at a friendly hostname like `canary.yourcompany.com`.

## 2. Mint a URL canary

```bash
honeytoken mint url --base https://canary.yourcompany.com --hint "internal wiki: 'click here for prod keys'"
```

Copy the `value` field and paste it into your internal wiki page as a hyperlink labeled "Production AWS keys (DO NOT SHARE)".

## 3. Watch it fire

Anyone who clicks the link (a real attacker, or a careless contractor) shows up in:

```bash
honeytoken events
```

```
2026-05-25T19:10:33+00:00   url_pT91kF2vL7zX   203.0.113.7   Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_0)
```

## 4. Scan logs for leakage

Periodically scan your code, log dumps, and pastes for any minted token:

```bash
find . -name '*.log' -o -name '*.txt' | xargs honeytoken scan
```

If a token shows up where it wasn't planted, that's the alert: it means the original location was read, copied, or exfiltrated.
