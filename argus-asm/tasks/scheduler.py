"""
Argus ASM — scheduler

Uses APScheduler to trigger run_scan_task on a recurring interval
for each target in TARGETS. This runs as a standalone process,
separate from the Celery worker — it just queues tasks on a timer.

Run with:
    python -m tasks.scheduler

The actual scan execution happens in the Celery worker process
(see tasks/scan_tasks.py) — this script only triggers it.
"""

import logging
import time

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger

from config.settings import settings
from tasks.scan_tasks import run_scan_task

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------- #
# Configure which targets to scan on a schedule.
# In a later phase this list would come from the database / API
# instead of being hardcoded here.
# ---------------------------------------------------------------------- #
TARGETS = [
    "scanme.nmap.org",
    # Add more authorised targets here
]


def trigger_scan(target: str) -> None:
    """Queue a scan task for *target* via Celery."""
    logger.info(f"Queueing scheduled scan for: {target}")
    run_scan_task.delay(target=target)


def main() -> None:
    scheduler = BlockingScheduler(timezone="UTC")

    interval_hours = settings.SCAN_INTERVAL_HOURS

    for target in TARGETS:
        scheduler.add_job(
            trigger_scan,
            trigger=IntervalTrigger(hours=interval_hours),
            args=[target],
            id=f"scan_{target}",
            name=f"Scheduled scan: {target}",
            replace_existing=True,
            # Run once immediately on startup, then on the interval
            next_run_time=None,
        )
        logger.info(
            f"Scheduled '{target}' every {interval_hours}h"
        )

    # Kick off an immediate first scan for every target on startup
    for target in TARGETS:
        trigger_scan(target)

    logger.info("Scheduler started. Press Ctrl+C to stop.")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Scheduler stopped.")


if __name__ == "__main__":
    main()
