"""Create the one-off 'Lab-proven fix report' product in Polar and a shareable checkout link.

Run once, after Manraj has signed in to Polar and made an Organization Access Token
(Polar dashboard > Settings > Developers, scopes products:write and checkout_links:write)
saved to ~/.config/polar/token (never commit it):

  python3 tools/polar_setup.py --dry-run          # print the requests, send nothing
  python3 tools/polar_setup.py                    # create product + checkout link, print the URL
  python3 tools/polar_setup.py --sandbox          # same against sandbox-api.polar.sh

Then paste the printed checkout URL into site/pages/pricing.html (the report card) and rebuild.
Re-running creates a second product: check the Polar dashboard first.
"""
import argparse, json, os, sys, urllib.request, urllib.error

NAME = "Lab-proven fix report"
DESCRIPTION = ("One app, one report. We rebuild your Supabase database from your repo's migrations in a lab, "
               "show which personal data the wrong people can read, and give you a fix your coding agent can "
               "apply, proven in the lab before you see it. Your engineer approves every change.")
SUCCESS_URL = "https://patchlabs.dev/check?paid=1&checkout_id={CHECKOUT_ID}"


def requests_for(amount, currency):
    product = {
        "name": NAME,
        "description": DESCRIPTION,
        "recurring_interval": None,  # one-time purchase
        "prices": [{"amount_type": "fixed", "price_amount": amount, "price_currency": currency}],
    }
    return product


def call(base, token, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                          "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit(f"Polar {path} failed: HTTP {e.code} {e.read().decode()[:600]}")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--amount", type=int, default=3900, help="minor units (3900 = 39.00)")
    ap.add_argument("--currency", default="gbp", help="gbp by default; use usd if Polar rejects gbp")
    ap.add_argument("--sandbox", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    base = "https://sandbox-api.polar.sh/v1" if a.sandbox else "https://api.polar.sh/v1"
    product = requests_for(a.amount, a.currency)
    if a.dry_run:
        print("POST", base + "/products/", json.dumps(product, indent=2))
        print("POST", base + "/checkout-links/", json.dumps({"product_id": "<id from above>", "success_url": SUCCESS_URL}, indent=2))
        return 0
    path = os.path.expanduser("~/.config/polar/token")
    if not os.path.exists(path):
        sys.exit(f"No token at {path}. Create an Organization Access Token in Polar first.")
    token = open(path).read().strip()
    p = call(base, token, "/products/", product)
    link = call(base, token, "/checkout-links/", {"product_id": p["id"], "success_url": SUCCESS_URL})
    print(json.dumps({"product_id": p["id"], "checkout_url": link.get("url")}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
