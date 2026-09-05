"""In-process scheduler that runs a scan for each authorised target periodically.

This is the lightweight alternative to the Celery + Redis stack described in the
report: it uses APScheduler so the whole platform can run from a single process
during development and demos. The Celery path can be added later without changing
the pipeline, because both simply call run_full_scan().

Usage:
    python -m argus.scheduler          # scans every SCAN_INTERVAL_HOURS
"""
import time

import config
from argus.pipeline import run_full_scan


def scan_all_authorised():
    for target in config.AUTHORISED_TARGETS:
        try:
            result = run_full_scan(target, use_db=True, correlate_cve=True)
            s = result["summary"]
            print(f"[scheduler] {target}: {s['assets']} assets, "
                  f"{s['open_ports']} ports, {s['changes']} changes, "
                  f"top risk {s['top_risk']}")
        except config.UnauthorisedTargetError as e:
            print(f"[scheduler] refused {target}: {e}")
        except Exception as e:  # pragma: no cover
            print(f"[scheduler] error scanning {target}: {e}")


def main():
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except Exception:
        print("APScheduler not installed; running a single sweep instead.")
        scan_all_authorised()
        return

    sched = BackgroundScheduler()
    hours = max(1, config.SCAN_INTERVAL_HOURS)
    sched.add_job(scan_all_authorised, "interval", hours=hours,
                  next_run_time=None)
    sched.start()
    print(f"[scheduler] started; scanning every {hours}h. Running first sweep now.")
    scan_all_authorised()
    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        sched.shutdown()
        print("[scheduler] stopped.")


if __name__ == "__main__":
    main()
