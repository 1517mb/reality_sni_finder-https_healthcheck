# REALITY SNI Finder & HTTPS Healthcheck

**English** | [Русский](README.ru.md)

Two standalone command-line scripts for finding SNI candidates for Xray REALITY and checking HTTPS certificates.

| Script | Purpose | Output |
| --- | --- | --- |
| [`reality_sni_finder.py`](reality_sni_finder.py) | Discover domains on HTTPS servers in neighboring IPv4 `/24` subnets; TLS 1.3, HTTP/2 and certificate verification are enabled by default | A domain list ranked by connection timing and IP distance |
| [`https_healthcheck.py`](https_healthcheck.py) | Check one domain's certificate and optionally send an HTTPS HEAD request | A JSON report and an exit code for automation |

The scripts run independently. They do not generate Xray configuration or pass results to each other automatically.

## Requirements and installation

Both scripts use the Python standard library. No packages need to be installed with `pip`.

| Component | SNI Finder | HTTPS Healthcheck |
| --- | --- | --- |
| Python | 3.9+ with an SSL build supporting TLS 1.3 | 3.11+ as specified by the script |
| `masscan` in `PATH` | Required | Not needed |
| `openssl` in `PATH` | Required for certificate parsing | Not needed; uses Python's `ssl` module |
| `curl` in `PATH` | Required; default verification needs HTTP/2 and TLS 1.3 support | Only required with `--http` |
| Privileges | `masscan` needs permission to send raw packets, typically through `sudo` | No elevated privileges required |

Use Python 3.11+ to run both scripts. The Finder examples below target Linux. Healthcheck can also run on Windows and macOS with Python and, for `--http`, `curl` installed.

Example system package installation on Debian/Ubuntu, from the project directory:

```bash
sudo apt update
sudo apt install python3 masscan curl openssl ca-certificates

python3 --version
curl --version
python3 reality_sni_finder.py --help
python3 https_healthcheck.py --help
```

Check your Python version. For Finder, `curl --version` should list the `HTTP2` feature and a TLS backend supporting TLS 1.3. Finder checks for all three external tools even with `--no-verify-h2`.

## Server deployment and launch menu

| Script | Purpose |
| --- | --- |
| [`deploy.sh`](deploy.sh) | Upload the current project files over SSH and run the server installer |
| [`install.sh`](install.sh) | Install Debian/Ubuntu system dependencies and check the environment |
| [`run.sh`](run.sh) | Open the project menu or launch either Python script directly |

The Bash launcher requires Python 3.11+. The menu has an ASCII project logo, English/Russian language switching, SNI discovery, HTTPS checks and a dependency check. It prompts for the target and options before running a check. Finder starts with `--blocks 0` in the menu; its Python CLI default remains `6`. Only the Finder command requests `sudo` when the launcher is run as a regular user.

### Upload directly from your computer

From the project directory on your computer, using Bash (Git Bash on Windows):

```bash
bash deploy.sh user@server

# Custom remote path; skip package installation if dependencies are already present.
bash deploy.sh --dir /home/user/reality-tools --skip-deps user@server
```

Replace `user@server` with your SSH destination. Deployment uses your SSH keys, agent or normal password authentication. The default remote directory is `reality-tools`, relative to the SSH user's home. It uploads the current versions of both Python scripts, the three Bash scripts, their tests, READMEs, license and Git configuration files `.gitignore`/`.gitattributes`, including uncommitted changes. Credentials, `.git` and generated results are excluded. Files shipped by the project are replaced on subsequent deployments; existing results are preserved. Use a dedicated project directory.

The installer uses `apt-get` on Debian/Ubuntu and requests `sudo` when necessary. It installs Python, Git, `masscan`, `curl`, `openssl` and CA certificates, then checks Python 3.11+, Python TLS 1.3 support, external tools and `curl` HTTP/2 support. If your system's Python is older, install a suitable interpreter and select it with `PYTHON_BIN`. On other Linux distributions, install dependencies yourself and use `--skip-deps`.

Open the menu after deployment:

```bash
ssh user@server
cd ~/reality-tools
bash run.sh

# Start with Russian or English menu labels.
RSF_LANG=ru bash run.sh
RSF_LANG=en bash run.sh
```

### Install from Git on the server

Once these files have been committed and pushed to the repository, you can also install via Git:

```bash
git clone https://github.com/1517mb/reality_sni_finder-https_healthcheck.git "$HOME/reality-tools"
cd "$HOME/reality-tools"
bash install.sh
bash run.sh
```

For updates to a Git checkout, run `git pull --ff-only` and then `bash install.sh --skip-deps`. Use `bash install.sh` if an update adds system dependencies. SSH uploads also work without publishing to GitHub.

### Run without the menu

```bash
bash run.sh check
bash run.sh finder --ref-ip 192.0.2.10 --blocks 0 --top 10
bash run.sh healthcheck --authorized --http my-domain.example
mkdir -p results
bash run.sh healthcheck --authorized --output results/report.json my-domain.example

# Select a different interpreter.
PYTHON_BIN=/usr/bin/python3.11 bash run.sh check
```

The Python flags and exit codes are preserved. `bash run.sh finder --help` and `bash run.sh healthcheck --help` show the corresponding Python help. Relative paths are resolved from the project directory. Finder defaults to `results/domains.txt`; menu-based HTTPS checks save timestamped JSON reports in `results/`. The direct `healthcheck` command prints to stdout unless `--output` is supplied; create its parent directory first if necessary. `RSF_RESULTS_DIR` changes the launcher's output directory. Generated `results/` files are ignored by Git. Finder output created through `sudo` may be owned by root.

For a scheduled HTTPS check, add a line like this with `crontab -e`, replacing the user, paths and authorized domain:

```cron
0 */6 * * * /bin/bash /home/user/reality-tools/run.sh healthcheck --authorized --http my-domain.example >> /home/user/reality-healthcheck.log 2>&1
```

This runs every six hours according to the server's timezone and appends reports to a log. Set an absolute `PYTHON_BIN` in the crontab if needed. Unattended Finder runs need a root job or an existing noninteractive privilege setup for `masscan`. Deployment and installation do not enable a schedule automatically.

### Verify the Bash helpers

```bash
python3 -m unittest discover -s tests -v
```

The tests in [`tests/test_shell_scripts.py`](tests/test_shell_scripts.py) use local substitutes for SSH, `sudo`, package installation and Python network checks, and make no server connections.

## Finding SNI candidates

### Quick start

Scan only addresses and ranges you are authorized to test. Automatically detecting your public IP does not grant permission to scan neighboring subnets.

```bash
# Detect the public IPv4 and scan its /24 plus 6 neighboring /24s on each side.
sudo python3 reality_sni_finder.py --verbose

# Set a reference IPv4 explicitly and restrict the scan to one /24.
# Replace 192.0.2.10 with an address in your authorized range.
sudo python3 reality_sni_finder.py --ref-ip 192.0.2.10 --blocks 0 --verbose

# Set the result count and output file, excluding known shared CDN domains.
sudo python3 reality_sni_finder.py --ref-ip 192.0.2.10 --blocks 0 --top 10 --no-include-generic --output candidates.txt
```

`192.0.2.10` is a documentation example address. Substitute an authorized IPv4 for an actual run. Without `--ref-ip`, the script queries `api.ipify.org`, followed by `ifconfig.me/ip` and `ipv4.icanhazip.com` if needed.

### How discovery works

1. Builds a range containing the reference `/24` and `N` subnets on each side. The default is 13 subnets, up to 3,328 IPv4 addresses; the range is smaller at IPv4 boundaries.
2. Uses a single `masscan` invocation to find open TCP port 443. The reference IP itself is excluded from subsequent checks.
3. Connects over TLS without SNI and extracts CN and DNS SAN entries from certificates using local `openssl`. Only connections negotiating TLS 1.3 are retained by default.
4. Expands a wildcard such as `*.example.com` into `example.com` and `www.example.com`, filters invalid names and limits the domains checked per IP.
5. By default, checks each domain/IP pair using `curl --resolve`: a HEAD request with the domain as SNI, TLS 1.3, a trusted certificate chain, a matching hostname and actually negotiated HTTP/2.
6. Ranks results and saves unique domains, keeping the best result for each domain.

The score is `curl time_appconnect` in milliseconds plus a penalty of up to 25 ms for numerical IP distance. `time_appconnect` measures time from the start of the request until the TLS connection completes, including TCP setup. Initial connection timing is used if this metric is unavailable; if neither timing is available, the fallback is 5,000 ms. Numerical IP proximity does not measure geographic proximity.

Servers that do not respond without SNI, or return a different virtual host's certificate without it, may be missed. The output contains candidates; the script does not test an actual REALITY connection.

### Finder options

Command-line arguments override environment variables. The defaults below assume no `RSF_*` variables are set.

| Option | Environment variable | Default | Description |
| --- | --- | --- | --- |
| `--ref-ip` | `RSF_REF_IP` | Autodetect | Reference IPv4; IPv6 is not supported |
| `--blocks` | `RSF_BLOCKS` | `6` | Neighboring `/24` subnets on each side; `0` scans only the reference `/24` |
| `--rate` | `RSF_RATE` | `4000` | `masscan` packet transmission rate, packets/s |
| `--wait` | `RSF_WAIT` | `2` | Wait for responses after packet transmission, seconds |
| `--timeout` | `RSF_TIMEOUT` | `8` | `curl` timeout in seconds; the initial TLS probe timeout is `max(2.5, timeout - 2)` |
| `--threads` | `RSF_THREADS` | `64` | Number of concurrent worker threads |
| `--max-per-ip` | `RSF_MAX_PER_IP` | `8` | Maximum domains extracted from CN/SAN per IP |
| `--top` | `RSF_TOPN` | `30` | Maximum unique domains to save |
| `--output` | — | `domains.txt` | Output file path |
| `--include-generic` / `--no-include-generic` | `RSF_INCLUDE_GENERIC` | `1` — enabled | Include domains from the built-in shared CDN list |
| `--verify-h2` / `--no-verify-h2` | `RSF_VERIFY_H2` | `1` — enabled | Use `curl` to verify HTTP/2 and the certificate; TLS 1.3 also depends on the next flag |
| `--require-tls13` / `--no-require-tls13` | — | Enabled | Require TLS 1.3 during the initial probe and `curl` verification |
| `-v`, `--verbose` | — | Disabled | Print domains, selected IPs and connection timings |
| `-h`, `--help` | — | — | Show help |

Use `1` or `0` for boolean environment variables. For example, `RSF_TOPN=10 python3 reality_sni_finder.py ...` sets the result count when `--top` is omitted. When running through `sudo`, pass flags: environment preservation depends on your `sudo` configuration.

`--no-include-generic` excludes only `cloudflaressl.com`, `cloudflare.com`, `akamai.net`, `akamaiedge.net`, `cloudfront.net`, `edgekey.net`, `edgesuite.net`, `fastly.net` and their subdomains. It is not a universal CDN filter.

`--no-verify-h2` skips the entire `curl` verification stage, including certificate trust and hostname checks. The initial TLS probe does not verify the certificate. `--no-require-tls13` allows TLS 1.2; HTTP/2 is still required while `--verify-h2` is enabled. Keep both checks enabled when finding REALITY candidates.

### Output file

`domains.txt`, or the path passed to `--output`, contains only domains, one per line, ordered from best to worst score:

```text
www.example.com
example.org
```

The UTF-8 file is **overwritten** after a successful search. Selected IPs and timings appear only with `--verbose` and are not saved in the file. Printed timing excludes the IP distance penalty. If no suitable results are found, no new output file is created and any previous file remains in place.

## Checking an HTTPS domain

### Quick start

Replace `my-domain.example` with a domain you are authorized to check. The required `--authorized` flag confirms that authorization.

```bash
# Check certificate trust, hostname and expiry.
python3 https_healthcheck.py --authorized my-domain.example

# Also send an HTTPS HEAD request and save a new JSON report.
python3 https_healthcheck.py --authorized --http --timeout 10 --output report.json my-domain.example
```

In PowerShell, you can use `python`:

```powershell
python https_healthcheck.py --authorized --http --output report.json my-domain.example
$LASTEXITCODE
```

### Behavior and options

The script accepts one ASCII/Punycode DNS name without a scheme, port, path or wildcard. IP addresses, ranges and domain lists are not accepted. The port is always 443.

The check uses normal DNS resolution, the specified domain as SNI and TLS 1.2 or newer. It verifies the certificate chain against the system trust store and the hostname against SAN; CN fallback is disabled. A certificate expiring in **30 days or less** produces a `warning`, which by itself does not cause a failure exit code.

| Option | Default | Description |
| --- | --- | --- |
| `domain` | Required | One DNS name to check |
| `--authorized` | Required | Confirm authorization to check the domain |
| `--http` | Disabled | After a successful certificate check, send one HTTPS HEAD request using `curl` |
| `--timeout` | `8` | Integer from 2 to 30 seconds for each stage separately; not a whole-run deadline |
| `--output` | Unset | Save the report to a new JSON file; its parent directory must exist |
| `-h`, `--help` | — | Show help |

With `--http`, the request connects directly, bypassing proxies and the user's `curl` configuration file. Redirects are not followed. HTTP/2 is not required: the report contains the HTTP version actually used. HTTP 4xx/5xx responses are recorded and do not by themselves count as diagnostic failures. If the certificate check fails, the HTTP stage is marked `skipped`.

### JSON report

The report is always printed to stdout after diagnostics and is also saved to a file when `--output` is set. Timestamps use UTC. This is an illustrative successful result with `--http`:

```json
{
  "schema_version": 1,
  "checked_at_utc": "2026-11-24T09:00:00Z",
  "domain": "my-domain.example",
  "port": 443,
  "ok": true,
  "certificate": {
    "status": "ok",
    "certificate_verified": true,
    "expires_at_utc": "2027-02-22T09:00:00Z",
    "days_remaining": 90.0,
    "expiry_warning": false
  },
  "http": {
    "status": "ok",
    "method": "HEAD",
    "http_version": "2",
    "http_status": 200
  }
}
```

Without `--http`, the `http` object is `{"status": "not_requested"}`. On failure, the relevant stage contains `status: "error"`, `error_type` and `error`; successful-result fields may be absent. The `ok` field reflects the success of the requested stages, including an acceptable certificate expiry warning.

Existing files and symbolic links are **not overwritten**. If the path is already occupied before diagnostics start, the script exits with code `2`; a write failure after diagnostics returns code `3`.

### Exit codes

| Code | Finder | Healthcheck |
| --- | --- | --- |
| `0` | Domain list written | Diagnostics succeeded; an expiry warning is acceptable |
| `1` | Discovery error, missing dependency or no suitable results | Certificate check or requested HTTP stage failed |
| `2` | Argument parsing error | Invalid arguments, missing `--authorized` or an occupied output path |
| `3` | Not explicitly used | Could not save the report after diagnostics |
| `130` | Not explicitly set | Check interrupted with Ctrl+C |

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `Required tool not found in PATH` | Install `masscan`, `curl` and `openssl`, and ensure they are available in Finder's execution environment, including under `sudo` |
| `masscan failed` | Raw-packet permissions, network interface availability and error details; reduce `--rate` if responses are being lost |
| No results after strict verification | HTTP/2/TLS 1.3 support in `curl`, server connectivity and system root certificates; increase `--timeout` if needed |
| Healthcheck reports a certificate error | Domain SAN, certificate expiry, the server's certificate chain, system time and root certificates |
| JSON report cannot be saved | Ensure the parent directory exists, is writable and the chosen filename is unused |

## License

Licensed under the GNU General Public License v3.0 (GPLv3). See [`LICENSE`](LICENSE) for the full text.
