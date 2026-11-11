"""Worker watchdog: runs inside the API (on Azure, so it keeps working when the Mac that runs the worker is down).

Every WATCHDOG_EVERY seconds it looks for checks that are waiting on a worker that has stopped, and emails the founder.
A stale heartbeat on its own is not an alert (the worker may simply be idle); stale heartbeat AND work waiting is.
One email per stall per ALERT_GAP, shared across API replicas through the kv table.
"""
import os, threading

from core import FOUNDER_EMAIL, SITE_URL, mail, pool

STALE_MIN = int(os.environ.get("WATCHDOG_STALE_MIN", "20"))      # heartbeat older than this counts as a stopped worker
ALERT_GAP_MIN = int(os.environ.get("WATCHDOG_ALERT_GAP_MIN", "180"))
_stop = threading.Event()


def check_once(c):
    """Returns the alert text if one was sent, else None."""
    row = c.execute(
        "SELECT (SELECT updated_at FROM kv WHERE key = 'worker_heartbeat') AS hb, "
        "       (SELECT count(*) FROM checks WHERE status IN ('queued', 'running')) AS waiting, "
        "       (SELECT min(created_at) FROM checks WHERE status IN ('queued', 'running')) AS oldest, "
        "       now() AS now").fetchone()
    stale = row["hb"] is None or (row["now"] - row["hb"]).total_seconds() > STALE_MIN * 60
    if not (stale and row["waiting"]):
        return None
    # claim the alert slot atomically, so two replicas don't both email
    claimed = c.execute(
        "INSERT INTO kv (key, value, updated_at) VALUES ('watchdog_alert', 'sent', now()) "
        "ON CONFLICT (key) DO UPDATE SET updated_at = now() "
        "WHERE kv.updated_at < now() - make_interval(mins => %s) RETURNING 1", (ALERT_GAP_MIN,)).fetchone()
    if not claimed:
        return None
    text = (f"{row['waiting']} check(s) are waiting and the worker hasn't checked in since {row['hb'] or 'ever'}.\n"
            f"Oldest waiting check created {row['oldest']}.\n\n"
            f"Is the Mac mini awake and is launchd's dev.patchlabs.worker running?\nAdmin: {SITE_URL}/admin\n")
    mail(FOUNDER_EMAIL, "PatchLabs worker has stopped: checks are waiting", text)
    return text


def start_loop(every):
    def loop():
        while not _stop.wait(every):
            try:
                with pool.connection() as c:
                    check_once(c)
            except Exception as e:
                print(f"watchdog: {e!r}", flush=True)
    _stop.clear()
    threading.Thread(target=loop, name="watchdog", daemon=True).start()


def stop_loop():
    _stop.set()
