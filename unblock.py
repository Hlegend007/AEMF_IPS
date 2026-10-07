"""Standalone command-line entry point for removing a MAC block."""

import argparse
import os
import platform

from config import BLOCK_LOG, SETTINGS, SIGNATURES_FILE
from aegis.logger import BlockLogger
from aegis.monitor import AegisMonitor
from aegis.signatures import SignatureDB


def main():
    parser = argparse.ArgumentParser(description="Remove an Aegis MAC block")
    parser.add_argument("mac")
    parser.add_argument("--admin", default=os.getenv("USERNAME", "administrator"))
    parser.add_argument("--reason", default="Manual unblock")
    args = parser.parse_args()

    monitor = AegisMonitor(
        SETTINGS,
        SignatureDB(SIGNATURES_FILE),
        BlockLogger(BLOCK_LOG),
        simulation=platform.system().lower() != "linux",
    )
    try:
        monitor.prevention.unblock(args.mac, args.admin, args.reason)
    except Exception as exc:
        parser.exit(1, f"Unblock failed: {exc}\n")
    print(f"UNBLOCK recorded for {args.mac}")


if __name__ == "__main__":
    main()