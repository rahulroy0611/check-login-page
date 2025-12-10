import requests
import argparse
import urllib.parse
import warnings
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup


parser = argparse.ArgumentParser(description="Check for login page on a given URLs.")
parser.add_argument("--file", required=True, help="Path to the file containing URLs.")
parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout seconds (default: 10)")
parser.add_argument("--max-hops", type=int, default=5, help="Max redirect/meta-refresh hops to follow (default: 5)")
parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification and suppress warnings (INSECURE)")
args = parser.parse_args()

session = requests.Session()
# Control TLS verification via the session so requests.get uses session.verify
session.verify = not args.insecure
# If user requested insecure mode, suppress urllib3 InsecureRequestWarning
if args.insecure:
    warnings.filterwarnings("ignore", category=InsecureRequestWarning)

def normalize_start_url(u: str) -> str:
    u = u.strip()
    if not u:
        return u
    if not (u.startswith('http://') or u.startswith('https://')):
        return 'http://' + u
    return u


def to_http_url(u: str) -> str:
    # Ensure the URL uses http scheme (keep host and path)
    u = u.strip()
    if not u:
        return u
    parsed = urllib.parse.urlparse(u if '://' in u else '//' + u, scheme='')
    # urlparse with '//' handles scheme-less URLs: netloc will be correct
    netloc = parsed.netloc or parsed.path
    path = parsed.path if parsed.netloc else ''
    if parsed.query:
        path = path + ('?' + parsed.query)
    return 'http://' + netloc + path

def follow_redirects_and_meta(start_url: str, session: requests.Session, timeout: float, max_hops: int):
    # Only follow HTTP (port 80) redirects and meta-refresh. If any redirect points to HTTPS,
    # we stop and treat the host as not serving the login page over HTTP as requested.
    url = normalize_start_url(start_url)
    # enforce http scheme
    if url.startswith('https://'):
        url = 'http://' + url[len('https://'):]
    hops = 0
    last_response = None
    while hops <= max_hops and url:
        try:
            # don't automatically follow redirects; handle Location header manually so we can
            # enforce scheme constraints (HTTP-only)
            resp = session.get(url, timeout=timeout, allow_redirects=False)
        except requests.exceptions.SSLError as e:
            if not session.verify:
                try:
                    resp = requests.get(url, timeout=timeout, allow_redirects=False, verify=False)
                except Exception as e2:
                    return None, f"SSL error accessing {url}: {e2}"
            else:
                return None, f"SSL error accessing {url}: {e}. Try running with --insecure to ignore certificate validation."
        except requests.RequestException as e:
            return None, f"Error accessing {url}: {e}"

        last_response = resp

        # If response is a redirect (3xx) and has Location, handle it but only follow if the next
        # URL uses http scheme. If it points to https, stop and exclude per requirements.
        if 300 <= resp.status_code < 400:
            loc = resp.headers.get('Location')
            if not loc:
                return None, f"Redirect ({resp.status_code}) from {url} without Location header"
            next_url = urllib.parse.urljoin(resp.url, loc)
            parsed = urllib.parse.urlparse(next_url)
            if parsed.scheme and parsed.scheme.lower() == 'https':
                return None, f"Redirects to HTTPS ({next_url}) — skipping since only HTTP (port 80) should be checked"
            # normalize to http
            if not parsed.scheme:
                next_url = 'http://' + next_url.lstrip('/')
            elif parsed.scheme.lower() != 'http':
                return None, f"Redirects to unsupported scheme ({parsed.scheme}) — skipping"

            hops += 1
            url = next_url
            continue

        # For non-redirect responses, check for meta-refresh hint in HTML but only follow if it points
        # to an HTTP URL; if meta-refresh points to HTTPS, treat as not serving login over HTTP.
        try:
            soup = BeautifulSoup(resp.text, 'html.parser')
            meta = soup.find('meta', attrs={"http-equiv": lambda v: v and v.lower() == 'refresh'})
            if meta and meta.get('content'):
                content = meta['content']
                parts = content.split(';')
                url_part = None
                if len(parts) > 1:
                    url_part = ';'.join(parts[1:]).strip()
                else:
                    url_part = content
                idx = url_part.lower().find('url=')
                if idx != -1:
                    extracted = url_part[idx+4:].strip().strip('"\'')
                    next_url = urllib.parse.urljoin(resp.url, extracted)
                    parsed = urllib.parse.urlparse(next_url)
                    if parsed.scheme and parsed.scheme.lower() == 'https':
                        return None, f"Meta-refresh redirects to HTTPS ({next_url}) — skipping since only HTTP should be checked"
                    if not parsed.scheme:
                        next_url = 'http://' + next_url.lstrip('/')
                    hops += 1
                    url = next_url
                    continue
        except Exception:
            # parsing error — just proceed to return the response as-is
            pass

        # Otherwise, we've got a non-redirect response on HTTP — return it for inspection
        return last_response, None

    return last_response, None


with open(args.file, 'r', encoding='utf-8') as f1:
    # summary collectors
    direct_logins = []    # (url, reason)
    link_logins = []      # (url, reason)

    for line in f1:
        orig = line.strip()
        if not orig:
            continue
        # Per request: only check HTTP first. If HTTP (port 80) is not open, skip scanning.
        http_url = to_http_url(orig)
        try:
            # quick check without following redirects so we detect whether HTTP port is reachable
            probe = session.get(http_url, timeout=args.timeout, allow_redirects=False)
            # If we get any response (including 3xx), HTTP is open; proceed with scanning starting from the HTTP URL
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as e:
            print(f"[!] HTTP not open for {orig} (will skip login scanning): {e}")
            continue
        except requests.RequestException:
            # Other request exceptions (including SSLError on redirect) — continue to scanning which will handle them
            pass

        resp, err = follow_redirects_and_meta(http_url, session, timeout=args.timeout, max_hops=args.max_hops)
        if err:
            print(f"[!] {err}")
            continue

        final_url = resp.url if resp is not None else orig
        try:
            soup = BeautifulSoup(resp.text, 'html.parser')

            def detect_login_by_heuristics(soup, text):
                # 1) explicit password input
                if soup.find('input', {'type': 'password'}):
                    return True, "input[type=password] found"

                # 2) inputs with names/ids/classes containing 'pass' or 'pwd'
                inputs = soup.find_all('input')
                for inp in inputs:
                    attrs = ' '.join([str(v) for k, v in inp.attrs.items() if v])
                    name_id_class = ' '.join([str(inp.get('name', '')), str(inp.get('id', '')), str(inp.get('class', ''))])
                    combined = (attrs + ' ' + name_id_class).lower()
                    if 'pass' in combined or 'pwd' in combined:
                        return True, f"input with pass indicator ({combined.strip()[:80]})"

                # 3) inputs with autocomplete indicating password
                for inp in inputs:
                    ac = inp.get('autocomplete', '')
                    if isinstance(ac, str) and 'password' in ac.lower():
                        return True, f"input autocomplete indicates password: {ac}"

                # 4) labels/placeholders/aria-labels mentioning password
                for inp in inputs:
                    ph = str(inp.get('placeholder', '')).lower()
                    aria = str(inp.get('aria-label', '')).lower()
                    if 'password' in ph or 'password' in aria:
                        return True, "placeholder/aria-label mentions password"
                labels = [l.get_text(separator=' ').lower() for l in soup.find_all('label')]
                for l in labels:
                    if 'password' in l or 'pwd' in l:
                        return True, "label mentions password"

                # 5) buttons or forms with login text (username + submit)
                form_texts = []
                for f in soup.find_all('form'):
                    form_texts.append(' '.join(f.stripped_strings).lower())
                pagestr = text.lower()
                if any('login' in ft or 'sign in' in ft or 'signin' in ft for ft in form_texts) or 'login' in pagestr:
                    # If page contains login text inside forms or page text, prefer to look for links/buttons
                    # which are stronger indicators of a login UI even if password input is injected.
                    pass

                # 5a) links that point to login/signup/register
                for a in soup.find_all('a'):
                    a_text = ' '.join(a.stripped_strings).lower()
                    if any(k in a_text for k in ('login', 'sign in', 'signin', 'signup', 'sign up', 'register', 'create account')):
                        return True, f"link with login text ({a_text[:80]})"

                # 5b) buttons and inputs that look like login/signup actions
                for btn in soup.find_all('button'):
                    btext = ' '.join(btn.stripped_strings).lower()
                    if any(k in btext for k in ('login', 'sign in', 'signin', 'signup', 'sign up', 'register', 'create account')):
                        return True, f"button with login text ({btext[:80]})"
                for inp in soup.find_all('input'):
                    itype = (inp.get('type') or '').lower()
                    if itype in ('submit', 'button'):
                        val = str(inp.get('value', '')).lower()
                        aria = str(inp.get('aria-label', '')).lower()
                        if any(k in val for k in ('login', 'sign in', 'signin', 'signup', 'sign up', 'register', 'create account')):
                            return True, f"input button with login text ({val})"
                        if any(k in aria for k in ('login', 'sign in', 'signin', 'signup', 'sign up', 'register', 'create account')):
                            return True, f"input button with aria-label ({aria})"

                # 5c) elements with role=button or aria-labels indicating login
                for el in soup.find_all(attrs={"role": "button"}):
                    el_text = ' '.join(el.stripped_strings).lower()
                    aria = str(el.get('aria-label', '')).lower()
                    if any(k in el_text for k in ('login', 'sign in', 'signin', 'signup', 'sign up', 'register')) or any(k in aria for k in ('login', 'sign in', 'signin', 'signup', 'sign up', 'register')):
                        return True, f"role=button element with login text ({(el_text or aria)[:80]})"

                # 6) search inline scripts for 'password' hints (obfuscated or dynamic)
                scripts = soup.find_all('script')
                for s in scripts:
                    stext = (s.string or '')
                    if isinstance(stext, str) and 'password' in stext.lower():
                        return False, "script contains 'password' keyword; may be dynamic"

                # 7) last resort: search raw page content for password indicators
                if 'password' in pagestr or 'pwd' in pagestr:
                    return False, "page contains 'password' keyword in text; may be dynamic"

                return False, "no indicators found"

            text = resp.text or ''
            found, reason = detect_login_by_heuristics(soup, text)
            reason_lower = (reason or '').lower()
            if found:
                # classify link/button-based detections separately
                if ('link with login text' in reason_lower or 'button with login text' in reason_lower or \
                    'input button' in reason_lower or 'role=button' in reason_lower or 'link with' in reason_lower):
                    link_logins.append((final_url, reason))
                    print(f"[+] Login link/button detected at: {final_url} ({reason})")
                else:
                    direct_logins.append((final_url, reason))
                    print(f"[+] Login page likely at: {final_url} ({reason})")
            else:
                # If heuristic inconclusive but page references password, mark as maybe
                if 'password' in (text or '').lower():
                    print(f"[?] Possibly a login page at: {final_url} ({reason})")
                else:
                    print(f"[-] No login page found at: {final_url} ({reason})")
        except Exception as e:
            print(f"[!] Error parsing {final_url}: {e}")

    # Print summary report
    print('\n===== Summary Report =====')
    print('\nDirect login pages detected:')
    if direct_logins:
        for u, r in direct_logins:
            print(f"- {u} ({r})")
    else:
        print('- None found')

    print('\nPages with login/sign-up links or buttons:')
    if link_logins:
        for u, r in link_logins:
            print(f"- {u} ({r})")
    else:
        print('- None found')



