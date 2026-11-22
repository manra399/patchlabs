"""Copies the pure analysis part of api/posture.py (Unreachable .. inspect) into actor/src/posture.py.

Run from the repo root after changing api/posture.py:  python3 actor/sync_posture.py
The Actor's Docker build context is actor/, so it can't import api/ directly.
"""
import pathlib, re

ROOT = pathlib.Path(__file__).resolve().parent.parent
src = (ROOT / "api/posture.py").read_text()
consts = src[src.index('UA = "PatchLabs-LivePosture'):src.index("class Unreachable(Exception):")]
consts = re.sub(r'^UA = ".*"$', 'UA = "PatchLabs-ApifyActor/1 (+https://patchlabs.dev/tools/headers-check)"', consts, count=1, flags=re.M)
body = src[src.index("class Unreachable(Exception):"):src.index("def has_code(site, code):")]

tax = (ROOT / "api/taxonomy.py").read_text()
live_tags = "\n".join(f"            {m.group(1)}," for m in re.finditer(r'^\s*("PL-0(?:2[7-9]|3[0-6]|40)": \(\[[^\]]*\], "[^"]+"\)),', tax, re.M))

HEADER = '''"""GENERATED from api/posture.py by actor/sync_posture.py. Do not edit by hand; edit api/posture.py and re-run the sync.

Pure headers/TLS/cookie analysis, the same logic as the free PatchLabs headers check, with core.ip_allowed and
taxonomy.tags inlined so the Actor has no database or server dependencies.
"""
import html, ipaddress, re, socket, ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import httpx

'''
SHIM = '''

class core:  # stand-in for api/core.py
    BLOCKED_NETS = [ipaddress.ip_network(n) for n in (
        "::/96", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32",
        "100.64.0.0/10", "168.63.129.16/32", "169.254.169.254/32")]

    @staticmethod
    def ip_allowed(ip):
        ip = ipaddress.ip_address(ip.split("%")[0])
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if any(ip in n for n in core.BLOCKED_NETS):
            return False
        return ip.is_global and not ip.is_multicast


class taxonomy:  # stand-in for api/taxonomy.py (live-line findings only)
    TAGS = {
@@TAGS@@
    }

    @staticmethod
    def tags(fid):
        cwe, owasp = taxonomy.TAGS.get(fid, ([], None))
        return {"cwe": list(cwe), "owasp": owasp}


'''.replace("@@TAGS@@", live_tags)

(ROOT / "actor/src/posture.py").write_text(HEADER + consts + SHIM + body.rstrip() + "\n")
print("wrote actor/src/posture.py")
