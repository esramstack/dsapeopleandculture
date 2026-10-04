#!/usr/bin/env python3
"""Keep the Content-Security-Policy in vercel.json in step with the script in index.html.

The CSP only lets the page's own inline <script> run, identified by its SHA-256 hash.
Any edit to that script changes the hash, so after editing index.html run:

    python3 qa/csp.py          # check (exit code 1 if out of date)
    python3 qa/csp.py --fix    # update vercel.json

If the hash is out of date the live page will not run at all, so always check before uploading.
"""
import base64, hashlib, json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
HTML, CONF = ROOT / "index.html", ROOT / "vercel.json"


def script_hash():
    scripts = re.findall(r"<script>(.*?)</script>", HTML.read_text(encoding="utf-8"), re.S)
    if len(scripts) != 1:
        sys.exit(f"Expected one inline <script> in index.html, found {len(scripts)}.")
    return "'sha256-" + base64.b64encode(hashlib.sha256(scripts[0].encode("utf-8")).digest()).decode() + "'"


def main():
    want = script_hash()
    conf = json.loads(CONF.read_text(encoding="utf-8"))
    hdr = next(h for rule in conf["headers"] for h in rule["headers"] if h["key"] == "Content-Security-Policy")
    have = re.search(r"'sha256-[A-Za-z0-9+/=]+'", hdr["value"])
    if have and have.group(0) == want:
        print("CSP hash is up to date:", want)
        return 0
    if "--fix" not in sys.argv:
        print("CSP hash is OUT OF DATE. Run: python3 qa/csp.py --fix")
        return 1
    hdr["value"] = re.sub(r"'sha256-[A-Za-z0-9+/=]+'", want, hdr["value"])
    CONF.write_text(json.dumps(conf, indent=2) + "\n", encoding="utf-8")
    print("Updated vercel.json:", want)
    return 0


if __name__ == "__main__":
    sys.exit(main())
