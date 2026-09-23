# Background dossier — demo-example
_Compiled 2026-09-23 10:51 (AEGIS panel)_
_Operator: demo_

## Findings

### Email route (`dry_headers.txt`)
- From: ceo@example.com
- To: vic@test.org
- Date: Tue, 22 Sep 2026 10:00:00 +0000
- Subject: invoice
- Message-ID: <a@b>
- Reply-To: evil@phish.ru
- Hops: 2
- hop0: from pc1 ([5.6.7.8]) by mx.evil.ru; Mon, 22 Sep 2026 10:00:00 +0000
- hop1: from mx.evil.ru (1.2.3.4) by mx.test.org with SMTP; Mon, 22 Sep 2026 10:01:00 +0000
- SPF: fail
- DKIM: none
- DMARC: fail
- FLAG: SPF fail — treat sender claims skeptically
- FLAG: DMARC fail — treat sender claims skeptically
- FLAG: Reply-To (evil@phish.ru) differs from From (ceo@example.com) — classic phish flag

## Field notes (operator, verbatim)
DEMO CASE — built on example.com (reserved documentation domain) with a fictional phish fixture. Everything below is real tool output; nothing here is a real target.

## Methods
- Sublist3r subdomain enumeration — skipped
- theHarvester sources: `crtsh,hackertarget,otx,rapiddns,urlscan,certspotter,duckduckgo` (no-key sources) — skipped
- Amass passive enum (no direct probing) — skipped
- Sherlock username sweep — skipped
- Maigret username sweep, top-100 sites — skipped
- gau historic URLs (otx+wayback providers) — skipped
- Pagodo GHDB quick file, 10 dorks — skipped
- Wayback CDX snapshots — archive unreachable (The read operation timed out)
- Photon crawl (emails + subdomains) — skipped
- Nmap service versions (ACTIVE probing — authorized targets only) — skipped
- Video metadata (yt-dlp, no download) — skipped
- Email header route analysis (offline) — 
- PhoneInfoga number footprint — skipped
- holehe email-account check — skipped
- Photo metadata — skipped (no photo attached)
- Not in automated runs (by design): SpiderFoot/Recon-ng (interactive consoles), BLE/Deauth (hardware radio + active attack), Maltego (GUI app), ExifTool card (file picker).

## Gaps & caveats
- Absence in these outputs is not absence in the world.
- Aggregator hits need primary-source confirmation before action.
- Username hits need a second discriminator (bio, photo, location) before attribution — name/handle alone is never enough.
- Wayback: archive unreachable (The read operation timed out).

## Raw evidence
`raw/` holds every tool's unedited output plus `run.log` with per-tool timings.
