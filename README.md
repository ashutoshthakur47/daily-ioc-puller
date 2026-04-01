# Daily IOC Puller

Pull the latest Indicators of Compromise (IOCs) from multiple threat intelligence sources in one place. No more jumping between ThreatFox, MalwareBazaar, OTX, and URLhaus to track newly discovered malware.

## Features

- **Consolidates IOCs** from 4 major threat intel platforms
- **Groups by malware family** - one entry per threat, not scattered across sources
- **Multiple IOC types** - IPs, domains, URLs, hashes, CVEs all in one view
- **Office-ready output** - copy/paste IOCs directly into spreadsheets
- **Filter by malware** - search for specific threats by name
- **Quick summary** - see at a glance what you're tracking
- **No file clutter** - prints to terminal, no Excel nonsense

## Data Sources

| Source | What | Days |
|--------|------|------|
| **ThreatFox** | Malware IOCs | Last 1 day |
| **MalwareBazaar** | Malware samples | Last 24 hours |
| **AlienVault OTX** | Threat pulses | Last 24 hours |
| **URLhaus** | Malicious URLs | Last 24 hours |

## Requirements

- Python 3.6+
- `requests` library

## Setup

### 1. Clone & install dependencies

```bash
git clone https://github.com/yourusername/daily-ioc-puller.git
cd daily-ioc-puller
pip install -r requirements.txt
```

### 2. Get API Keys

You need 2 API keys (both free):

**abuse.ch Auth-Key** (covers ThreatFox, MalwareBazaar, URLhaus):
- Visit: https://auth.abuse.ch/
- Register for free account
- Copy your Auth-Key

**AlienVault OTX API Key** (optional, for extra coverage):
- Visit: https://otx.alienvault.com/
- Go to Settings > API
- Copy your API key

### 3. Set Environment Variables

Store your keys as environment variables. Never hardcode them in the script.

**Windows (PowerShell):**
```powershell
$env:ABUSECH_AUTH_KEY = "your_auth_key_here"
$env:OTX_API_KEY = "your_otx_key_here"
```

**Windows (cmd.exe):**
```cmd
set ABUSECH_AUTH_KEY=your_auth_key_here
set OTX_API_KEY=your_otx_key_here
```

**Linux/Mac (temporary):**
```bash
export ABUSECH_AUTH_KEY="your_auth_key_here"
export OTX_API_KEY="your_otx_key_here"
```

**Linux/Mac (permanent - add to ~/.bashrc or ~/.zshrc):**
```bash
export ABUSECH_AUTH_KEY="your_auth_key_here"
export OTX_API_KEY="your_otx_key_here"
```

## Usage

### Basic run (full detailed report)
```bash
python daily_ioc_puller.py
```

Shows all malware families with:
- Last seen timestamp
- Source(s)
- All IPs/domains/hashes listed one per line
- CVE references

### Quick summary (table view)
```bash
python daily_ioc_puller.py --summary
```

Shows: malware name, count of IPs/domains/hashes, sources

### Search specific malware
```bash
python daily_ioc_puller.py --filter remcos
```

Returns only matches for "remcos" (case-insensitive, partial match)

### List all families
```bash
python daily_ioc_puller.py --list
```

Just shows the names of discovered families

### Save output to file
```bash
python daily_ioc_puller.py > todays_iocs.txt
```

## Example Output

```
────────────────────────────────────────────────────────────────────────────────
[1] MALWARE: WIN.REMCOS
────────────────────────────────────────────────────────────────────────────────
  Last Seen  : 2026-04-01 10:00
  Sources    : ThreatFox
  Confidence : 100%
  Total IOCs : 12 (IPs: 2, Domains: 8, Hashes: 2)
  CVEs       : CVE-2024-1234

  ┌─ IPs (2) ─────────────────────────────
  │ 192.168.1.100:443
  │ 45.33.32.156:8080
  └─────────────────────────────────────────────

  ┌─ Domains (8) ─────────────────────────────
  │ remcos-c2.com
  │ malware-drop.net
  │ evil-panel.ru
  ...
```

Simply select and copy the IOCs you need, paste into your tracking sheet.

## How It Works

1. **Pulls data** from all 4 sources in parallel
2. **Normalizes** entry formats (different APIs return different structures)
3. **Merges** all IOCs for the same malware into one entry
4. **Deduplicates** - if multiple sources report the same IOC, it's shown once
5. **Sorts** by malware name alphabetically
6. **Displays** in clean, copy-paste format

## Error Handling

If any source fails or returns bad data:
- Script continues (doesn't crash)
- Warning shown: `[WARN] GET failed: ...`
- Partial results displayed

No API key? Script adapts:
- Without `ABUSECH_AUTH_KEY`: abuse.ch sources return 401 (skipped)
- Without `OTX_API_KEY`: OTX is skipped, other sources work fine

## Daily Automation (Optional)

### Windows Task Scheduler
```batch
# Create a .bat file (e.g., run_ioc_puller.bat)
@echo off
set ABUSECH_AUTH_KEY=your_key_here
set OTX_API_KEY=your_key_here
cd C:\path\to\daily-ioc-puller
python daily_ioc_puller.py --summary >> logs\ioc_log.txt
```

Then schedule in Task Scheduler to run daily.

### Linux/Mac Cron
```bash
# Edit crontab: crontab -e
0 8 * * * export ABUSECH_AUTH_KEY="..." && export OTX_API_KEY="..." && cd /path/to/daily-ioc-puller && python daily_ioc_puller.py --summary >> logs/ioc_log.txt
```

## Troubleshooting

**Q: I get "401 Unauthorized" for all sources**
- Make sure `ABUSECH_AUTH_KEY` is set correctly
- Double-check no extra spaces or quotes

**Q: OTX returns nothing**
- Verify `OTX_API_KEY` is correct
- Check your OTX account actually has subscribed feeds

**Q: Nothing shows up**
- Maybe no new IOCs in the last 24h (happens on quiet days)
- Try `--list` to see if any families exist
- Check warning messages for API issues

**Q: Can I pull older data?**
- Current: pulls last 24 hours only
- Each API has limits (ThreatFox: up to 7 days)
- Edit the `days` parameter in `pull_threatfox()` if needed

## License

MIT

## Contributing

Issues and pull requests welcome. For security issues, please email privately instead of posting publicly.

## Disclaimer

This tool pulls data from public threat intelligence feeds. Use it for your own security research and threat tracking. We're not responsible for how you use this data.
