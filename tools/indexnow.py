"""Tell Bing (and the other IndexNow engines: Yandex, Seznam, Naver) about every URL in docs/sitemap.xml.

  python3 tools/indexnow.py            # after a deploy is live
IndexNow needs no account: the key file at https://patchlabs.dev/<key>.txt proves we own the site.
"""
import json, re, urllib.request

KEY = "0cee70e020aa4529875b4ee20a92d20c"
HOST = "patchlabs.dev"

urls = re.findall(r"<loc>([^<]+)</loc>", open("docs/sitemap.xml").read())
body = json.dumps({"host": HOST, "key": KEY, "keyLocation": f"https://{HOST}/{KEY}.txt", "urlList": urls}).encode()
req = urllib.request.Request("https://api.indexnow.org/indexnow", data=body, headers={"Content-Type": "application/json; charset=utf-8"})
with urllib.request.urlopen(req, timeout=30) as r:
    print(f"IndexNow: {len(urls)} URLs, HTTP {r.status}")
