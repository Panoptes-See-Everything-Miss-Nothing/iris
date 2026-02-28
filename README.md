<p align="center">
  <img src="assets/branding/panoptes-logo.png" alt="Panoptes Logo" width="200">
</p>

<h1 align="center">Panoptes</h1>
<p align="center"><em>See Everything. Miss Nothing.</em></p>

<p align="center">
  <a href="https://en.cppreference.com/w/cpp/20"><img src="https://img.shields.io/badge/C%2B%2B-20-blue.svg" alt="C++20"></a>
  <a href="https://www.microsoft.com/windows"><img src="https://img.shields.io/badge/platform-Windows%2010%2B-0078d4.svg" alt="Platform"></a>
  <a href="#build"><img src="https://img.shields.io/badge/arch-x64%20%7C%20x86-green.svg" alt="Architecture"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-GPLv3-lightgrey.svg" alt="License"></a>
</p>

---

<p align="center">
  Iris a part of the <strong>Panoptes Platform</strong>.<br>
  🔎 Check the <a href="https://github.com/Panoptes-See-Everything-Miss-Nothing">Panoptes homepage here</a>.
</p>

# Iris — The Messenger

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

---

## Documentation

Coming soon.

---

# Core Contributors

## Vaibhav Kakade
- 💼 [![LinkedIn](https://img.shields.io/badge/LinkedIn-Vaibhav%20Kakade-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/vgkakade/)
- 𝕏 [![X](https://img.shields.io/badge/X-@vk_appledore-000000?logo=x&logoColor=white)](https://x.com/vk_appledore)
- 🧑‍💻 [![GitHub](https://img.shields.io/badge/GitHub-vkappledore-181717?logo=github&logoColor=white)](https://github.com/vkappledore/)

## Sanoop Thomas
- 💼 [![LinkedIn](https://img.shields.io/badge/LinkedIn-s4n7h0-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/s4n7h0/)
- 𝕏 [![X](https://img.shields.io/badge/X-@s4n7h0-000000?logo=x&logoColor=white)](https://x.com/s4n7h0)
- 🧑‍💻 [![GitHub](https://img.shields.io/badge/GitHub-s4n7h0-181717?logo=github&logoColor=white)](https://github.com/s4n7h0/)

## Narendra Shinde
- 💼 [![LinkedIn](https://img.shields.io/badge/LinkedIn-narendrashinde-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/narendrashinde/)
- 𝕏 [![X](https://img.shields.io/badge/X-@nushinde-000000?logo=x&logoColor=white)](https://x.com/nushinde)
- 🧑‍💻 [![GitHub](https://img.shields.io/badge/GitHub-Nushinde-181717?logo=github&logoColor=white)](https://github.com/Nushinde)

## Kapil Khot
- 💼 [![LinkedIn](https://img.shields.io/badge/LinkedIn-Kapil%20Khot-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/kapil-khot-50466952/)
- 𝕏 [![X](https://img.shields.io/badge/X-@kapil_khot-000000?logo=x&logoColor=white)](https://x.com/kapil_khot)
- 🧑‍💻 [![GitHub](https://img.shields.io/badge/GitHub-SlidingWindow-181717?logo=github&logoColor=white)](https://github.com/SlidingWindow)
---

# Contributing

Community contributions are welcome.

If you have:

- Detection artefacts  
- Version mapping improvements  
- Edge-case installation samples  
- Performance optimisations  
- API improvements
- Test bed and/or test cases
- Access to vendor-specific advisories that are only available to licensed customers (for validation and correlation testing purposes — proprietary content will not be redistributed)
   - Some enterprise products publish vulnerability advisories exclusively through customer portals. 
   - If you are a licensed customer and are willing to help validate version-to-CVE mappings, your collaboration can significantly improve coverage for those platforms.
      - Contributors are responsible for ensuring they have appropriate vendor approval and rights to share any non-public advisory information.

Open an issue or submit a pull request.

For vulnerabilities, security misconfigurations, or sensitive disclosures, please submit a private issue (feature coming soon) or contact **Kapil Khot** directly.

We take responsible disclosure seriously and will ensure proper acknowledgment and credit for all valid findings.

Let’s build something that actually sees everything.


---

# Licensing

Panoptes is licensed under the **GNU General Public License v3 (GPLv3)**.

This means:

- You are free to **use, modify, and distribute** Panoptes.
- Any modified or derivative works must also be licensed under **GPLv3**.
- See the [`LICENSE`](LICENSE) file for full terms.

For more details on GPLv3, visit: [https://www.gnu.org/licenses/gpl-3.0.en.html](https://www.gnu.org/licenses/gpl-3.0.en.html)

---

