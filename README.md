# Iris — Messenger of the Gods

Iris is a CVE data ingestion pipeline that fetches vulnerability data from the [National Vulnerability Database (NVD)](https://nvd.nist.gov/) and stores it in a PostgreSQL database for downstream consumption.

Iris, the messenger of the Gods — acts as the bridge between NVD and the rest of the Panoptes platform.

---

## What It Does

- Downloads yearly NVD JSON feed files (2002 to present) and parses them into the database
- Fetches live CVE data from the NVD REST API with concurrent pagination
- Upserts CVE records, affected packages, version ranges, and CVSS v2/v3.1 scores
- Skips CVEs that already exist in the database unless their `lastModified` date has updated

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Data Sources                             │
│                                                                 │
│   NVD JSON Feeds                    NVD REST API               │
│   (2002 → present)                  /rest/json/cves/2.0        │
│   nvdcve-2.0-{year}.json.gz         (paginated, async)         │
└──────────────┬──────────────────────────────┬───────────────────┘
               │                              │
               ▼                              ▼
┌──────────────────────────┐   ┌──────────────────────────────────┐
│   nvd_feed_scraper.py    │   │         nvd_parser.py            │
│                          │   │                                  │
│ • ThreadPoolExecutor     │   │ • aiohttp async session          │
│   (3 workers)            │   │ • Paginated fetch (2000/page)    │
│ • Streams .gz → temp     │   │ • Retry with exponential backoff │
│   file → atomic rename   │   │ • Merges pages into one dict     │
└──────────────┬───────────┘   └──────────────────┬───────────────┘
               │                                  │
               └──────────────┬───────────────────┘
                              │  raw NVD JSON
                              ▼
              ┌───────────────────────────────┐
              │          cve_parser.py        │
              │                               │
              │ • Filters existing/unchanged  │
              │   CVEs (cve_lookup.py)        │
              │ • Parses CPE strings          │
              │ • Extracts CVSS v2 / v3.1     │
              │ • Returns DB-ready dicts      │
              └───────────────┬───────────────┘
                              │  parsed CVE objects
                              ▼
              ┌───────────────────────────────┐
              │  cve_importer.py / cvss.py    │
              │                               │
              │ • Upserts CVEs                │
              │ • Upserts Vendors             │
              │ • Upserts VulnerablePackages  │
              │ • Upserts VulnerableVersions  │
              │ • Upserts CVSS v2 / v3.1      │
              └───────────────┬───────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │      PostgreSQL Database      │
              │         (Docker)              │
              └───────────────────────────────┘
```

---

## Database Schema

| Table | Description |
|---|---|
| `cves` | Core CVE record — ID, description, status, dates, source |
| `vendors` | Vendor names extracted from CPE strings |
| `vulnerable_packages` | Affected packages linked to a CVE and vendor |
| `vulnerable_versions` | Version ranges (start/end/fixed) per package |
| `cvss_v2` | CVSS v2 scores and vector components |
| `cvss_v31` | CVSS v3.1 scores and vector components |

### Relationships

```
cves (1) ──────────────── (N) vulnerable_packages
                                      │
                          (1) ────── (N) vulnerable_versions

cves (1) ──────────────── (1) cvss_v2
cves (1) ──────────────── (1) cvss_v31

vendors (1) ────────────── (N) vulnerable_packages
```

---

## Pre-requisites

- Docker and Docker Compose
- Python 3.13
- An [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (optional but recommended to avoid rate limits)

---

## Setup

### 1. Clone the repository

```bash
git clone <repo-url>
cd Iris
```

### 2. Configure environment variables

Create a `.env` file in the project root:

```env
DB_USERNAME=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=localhost
DB_PORT=5432
DATABASE=cvedb
NVD_API_KEY=your_nvd_api_key
```

### 3. Install Python 3.13 with venv support

```bash
sudo apt update
sudo apt install python3.13 python3.13-venv
```

### 4. Create and activate a virtual environment

```bash
python3.13 -m venv .venv
source .venv/bin/activate
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Start the database

```bash
docker compose up -d
```

### 7. Run database migrations

```bash
alembic upgrade head
```

### 8. Run Iris

```bash
python -m src.core.main
```

---

## Optional: direnv

[direnv](https://direnv.net/) can automatically load your `.env` when you enter the project directory.

```bash
sudo apt install direnv
```

Add to `~/.bashrc` (or `~/.zshrc` for zsh):

```bash
eval "$(direnv hook bash)"
```

Reload your shell, then allow direnv in the project folder:

```bash
source ~/.bashrc
direnv allow
```

---

## Development Tools

| Tool | Purpose |
|---|---|
| `black` | Code formatter |
| `pre-commit` | Git hook runner |
| `alembic` | Database migrations |

Install black:

```bash
sudo apt install black
```

---

## Project Structure

```
src/
├── core/
│   └── main.py               # Entry point — orchestrates JSON feed and API runs
├── crud/
│   ├── cve_importer.py       # Upserts CVEs, packages, versions into DB
│   ├── cve_lookup.py         # Checks DB for existing / updated CVEs
│   └── cvss_scores.py        # Upserts CVSS v2 and v3.1 scores
├── models/
│   ├── cve.py                # CVE ORM model
│   ├── vendor.py             # Vendor ORM model
│   ├── vulnerable_package.py # VulnerablePackage ORM model
│   ├── vulnerable_version.py # VulnerableVersion ORM model
│   └── cvss.py               # CVSSv2 and CVSSv31 ORM models
├── utils/
│   ├── nvd_feed_scraper.py   # Downloads yearly .json.gz feed files
│   ├── nvd_parser.py         # Reads JSON files and calls NVD REST API
│   └── cve_parser.py         # Parses raw NVD data into DB-ready dicts
├── fixtures/                 # Cached yearly JSON feed files (gitignored)
└── settings.py               # DB connection, engine, and config
```
