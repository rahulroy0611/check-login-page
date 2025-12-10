# check_login_page

A small command-line tool that scans a list of domains/URLs and reports which hosts serve a login entry over HTTP (port 80). The script focuses on HTTP-only checks (port 80) and will exclude domains that do not respond on port 80 or that redirect from HTTP to HTTPS.

Goal
- Detect which domains are listening on port 80 (HTTP) and have a login entry point (form, link, or button) accessible over HTTP.
- Avoid scanning HTTPS-only hosts: skip domains that do not serve content on port 80 or that redirect to HTTPS.

What the tool can produce
- For each domain in your input file, it will print one of:
  - `[+] Login page likely at: http://... (reason)` — a strong indicator (e.g., `input[type=password]`, login link/button).
  - `[?] Possibly a login page at: http://... (reason)` — weaker indicators (e.g., page text or scripts mentioning `password`, or dynamic JS-driven forms).
  - `[-] No login page found at: http://... (reason)` — HTTP responded but no login indicators detected.
  - `[!] HTTP not open for <domain> (will skip login scanning): <error>` — port 80 not reachable, domain skipped.
  - `[!] Redirects to HTTPS (https://...) — skipping since only HTTP (port 80) should be checked` — HTTP responded with a redirect to HTTPS and is excluded.
  - `[!] Error accessing <url>: <error>` — network/HTTP errors encountered while probing or scanning.

Prerequisites
- Python 3.8+ (3.10/3.11 recommended)
- Windows (commands below use `cmd.exe`) — Linux/macOS will work with equivalent shell commands.

Install dependencies
Open `cmd.exe` in the project folder (where `requirements.txt` exists) and run:

```cmd
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The current `requirements.txt` includes:
- `beautifulsoup4`
- `requests`

Optional (JS-rendering)
- This project currently uses static HTML heuristics and does not include a JavaScript-rendering mode. Some login forms are injected dynamically by client-side JavaScript and will not appear in the static HTML. For those cases, consider using an external headless browser (Playwright, Selenium, etc.) or request an enhancement to add a `--render` mode.

Usage
- Basic run (HTTP-only checks):
```cmd
python check_login_page.py --file urls.txt
```
- Use a custom timeout or max hops (meta-refresh/redirects):
```cmd
python check_login_page.py --file urls.txt --timeout 5 --max-hops 3
```
- Insecure mode (only relevant if an HTTP probe ends up touching HTTPS due to environment):
```cmd
python check_login_page.py --file urls.txt --insecure
```
Note: `--insecure` disables certificate verification and suppresses TLS warnings. This is INSECURE — only use for testing.

Input file format
- `urls.txt` should contain one host or URL per line. Examples:
```
example.com
http://example.org/somepath
https://sub.example.net
```
The script normalizes entries to an HTTP URL and probes port 80 (e.g., `http://example.com`).

How it works (high level)
- For each input line the script:
  1. Builds the HTTP URL (ensures `http://`) and probes port 80 with a quick non-redirecting GET.
  2. If the HTTP probe fails (connection/timeout), the host is skipped and marked as not serving HTTP.
  3. If the HTTP probe returns a response (including 3xx), the script will manually follow HTTP redirects and meta-refresh entries — but will NOT follow redirects to HTTPS. If an HTTP response redirects to HTTPS, the host is excluded per your requirement.
  4. When an HTTP page is reached, the script performs static HTML heuristics to detect login presence:
     - Looks for `input[type=password]`.
     - Checks input `name`, `id`, or `class` for `pass`/`pwd` indicators.
     - Checks `autocomplete` attributes for `password`.
     - Checks placeholder/aria-label/label text for `password`.
     - Detects links (`<a>`), buttons (`<button>`), or submit inputs whose text/value contains `login`, `sign in`, `signin`, `signup`, `sign up`, `register`, `create account`.
     - Scans inline scripts and page text for `password` as a weaker indicator (may indicate JS-driven forms).
  5. Prints results with a short reason message.

Limitations & notes
- The tool is intentionally HTTP-only. If a site only supports HTTPS and refuses/redirects HTTP, it will be excluded. This is by design to identify only hosts serving login pages on port 80.
- Static HTML heuristics can produce false positives (pages that mention `login` or `password` without providing a login UI) and false negatives (JS-injected forms). Use the optional JS rendering mode for more reliable results on modern sites.
- `--insecure` affects TLS checks when the code must attempt HTTPS (fallbacks/edge cases). Prefer not to use it broadly.

Examples
- urls.txt contains:
```
example.com
tmf-group.com
app.prismacloud.io
```
- Run:
```cmd
python check_login_page.py --file urls.txt
```
- Example possible output:
```
[!] HTTP not open for app.prismacloud.io (will skip login scanning): HTTPS only
[!] Redirects to HTTPS (https://tmf-group.com) — skipping since only HTTP (port 80) should be checked
[+] Login page likely at: http://example.com (input[type=password] found)
```

- Add a summary report at the end that aggregates how many hosts were:
  - scanned successfully,
  - excluded due to no HTTP,
  - excluded due to redirect-to-HTTPS,
  - flagged as login present.

License & Safety
- This script is provided as-is for internal testing and reconnaissance of URLs you own or are authorized to test. Do not scan targets without permission.
