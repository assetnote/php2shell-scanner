# php2shell-scanner

A command-line tool for detecting CVE-2026-109618 and CVE-2026-109619 in PHP applications.

## How It Works

The scanner sends a minimal multipart control request followed by up to three crafted multipart probes. The probes use PHP array keys nested 62 levels deep and increase from 1 MiB to 20 MiB, matching the detection logic used by Assetnote's internal scanner.

A target is reported vulnerable when the probe produces a PHP memory-exhaustion error, a differential empty HTTP 500, a PHP-FPM worker failure, or an advertised PHP version known to be unpatched. Initial 5xx responses, common request-rejection statuses, and nonempty HTTP 500 responses without the PHP fatal-error signature are not treated as crash signals.

The scanner tests `/index.php` by default. A path supplied in the URL is preserved, and `--path` or `--path-file` can test custom paths. phpMyAdmin targets are automatically retested at `/show_config_errors.php`. Redirects are not followed.

### SAPI Modes

The default `--sapi auto` mode applies both mod_php and PHP-FPM verdict rules, matching the combined behavior of Assetnote's postmodules. Use `--sapi mod_php` or `--sapi fpm` to restrict detection to a known SAPI.

### Network Impact

Each tested path may receive a 42-byte control request and three probes totalling about 29 MiB. Probing stops as soon as the verdict is settled, and duplicate input URLs are scanned once.

### Lightweight WAF check

Use `--waf-check` to check edge mitigation with small requests instead of the
memory-pressure probes:

```
python3 scanner.py -u https://example.com/upload.php --waf-check
python3 scanner.py -l hosts.txt --waf-check -o waf-results.json
```

Each tested path receives a benign multipart control request followed by an
approximately 9 KB shaped request containing `PHP_SESSION_UPLOAD_PROGRESS`,
three `t[]` fields, and two 4 KB file parts. Both requests use the same cookie
context; a custom `Cookie` header is preserved. No large probes are built or sent
in this mode. Control redirects and connection failures stop the check early.

| WAF verdict | Meaning |
|---|---|
| `BLOCKED` | Control returned 2xx or 404; shaped request returned 403 with a Cloudflare block-page marker. |
| `NOT BLOCKED` | Control and shaped request returned 2xx or 404; no blocking was observed for this layout. |
| `INCONCLUSIVE` | The control was rejected or failed at the server, or the shaped response did not establish Cloudflare blocking. Includes non-Cloudflare 403 responses. |
| `REDIRECT` | A request redirected. Retest the intended endpoint; redirects are not followed. |
| `ERROR` | A request failed or the target URL was invalid. |

These results describe only the tested request shape. A Cloudflare block page
does not identify the rule that fired or prove protection against other payloads.
An accepted request does not prove that PHP handled it. This mode does not assess
PHP patch status or exploitability; verify installed versions separately.

The existing URL, path, header, timeout, TLS, and threading options apply.
`--sapi` applies only to the default vulnerability scan. JSON output includes all
WAF results without requiring `--all-results`, with `mode: "waf"`, a nullable
`waf_blocked` field, and `vulnerable: null`. With multiple paths, a host is reported
blocked only if every tested path is blocked; an observed `NOT BLOCKED` path takes
precedence over an inconclusive path. `--quiet` prints only checks that are not
confirmed blocked. Exit status is 0 only when every tested target/path is blocked,
1 otherwise, or 2 if the output file cannot be written.

## Requirements

- Python 3.9+
- h11
- tqdm

## Installation

```
pip install -r requirements.txt
```

## Usage

Scan a single host:

```
python3 scanner.py -u https://example.com
```

Scan a list of hosts:

```
python3 scanner.py -l hosts.txt
```

Scan with multiple threads and save results:

```
python3 scanner.py -l hosts.txt -t 20 -o results.json
```

Scan with custom headers:

```
python3 scanner.py -u https://example.com -H "Authorization: Bearer token" -H "Cookie: session=abc"
```

Scan a custom path:

```
python3 scanner.py -u https://example.com --path /phpinfo.php
python3 scanner.py -u https://example.com --path /index.php --path /admin.php
python3 scanner.py -u https://example.com --path-file paths.txt
```

Use only PHP-FPM verdict rules:

```
python3 scanner.py -u https://example.com --sapi fpm
```

## Options

```
-u, --url         Single URL to check
-l, --list        File containing hosts (one per line)
-t, --threads     Number of concurrent threads (default: 10)
--timeout         Request timeout in seconds (default: 60)
-o, --output      Output file for results (JSON)
--all-results     Save all results, not just vulnerable hosts
-k, --insecure    Disable TLS certificate verification
-H, --header      Custom header (can be used multiple times)
-v, --verbose     Show verdict reasons and response snippets
-q, --quiet       Only output vulnerable hosts
--no-color        Disable colored output
--waf-check       Check selective WAF blocking using only small multipart requests
--sapi            Verdict rules: auto, mod_php, or fpm (default: auto)
--path            Custom path to test (can be used multiple times)
--path-file       File containing paths to test (one per line)
```

## Credits

The first, original discovery of php2shell is attributed to the Calif team. You can read their write up here: [https://calif.io/php2shell/](https://calif.io/php2shell/).

The scanner was built by the Assetnote Security Research Team using logic built for [Searchlight's Exposure Platform](https://www.slcyber.io/exposure).

The lightweight WAF-check technique and multipart layout are adapted from
[php2shell_waf_check](https://github.com/msuiche/php2shell_waf_check) by
Matt Suiche, Tolmo ([@msuiche](https://github.com/msuiche)).

## Output

Results are printed to the terminal. When using `-o`, vulnerable hosts are saved to a JSON file with the verdict reason and redacted HTTP request/response evidence.

## Limitations

On specific PHP configurations, the scanner may report a false positive when its multipart probe exceeds PHP's `memory_limit`. Patched and vulnerable versions can then return the same empty HTTP 500 response.

This was reproduced on patched PHP 8.4.27 with `memory_limit` values from **2M to 32M**, and on PHP 8.3.36 at **128M** when `max_multipart_body_parts` is set to **2785 or higher**. The exact threshold may vary between builds.

When PHP does not disclose its version, the scanner cannot distinguish this safe post-patch OOM from the vulnerable pre-patch behavior. Results should therefore be verified against the installed PHP version and any vendor backports

## Tests

After installing the requirements, run `python3 -m unittest discover -s tests -v`.
The tests use mocked responses and a local HTTP server; they do not probe external
targets.
