from __future__ import annotations

import argparse
import sys
import time

from lace.config import ConfigError, load_settings
from lace.engine import analyze
from lace.enrichment import IocError, load_ioc_list
from lace.parsers import ParseStats, parse
from lace.reporters.json_reporter import write_json
from lace.reporters.table_reporter import print_table


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lace",
        description="Log Anomaly Correlation Engine",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="Analyze log files and emit alerts")
    run.add_argument("--config", required=True, help="Path to YAML settings")
    run.add_argument(
        "--input",
        nargs="+",
        default=None,
        help="One or more log files (default: config default_input)",
    )
    run.add_argument(
        "--format",
        required=True,
        choices=("csv", "jsonl", "syslog"),
    )
    run.add_argument("--ioc-list", default=None, help="Override IOC CSV path")
    run.add_argument(
        "--output",
        default=None,
        help="JSON alerts output path (default: config default_output)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "run":
        return 2
    started = time.perf_counter()
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 1

    ioc_path = args.ioc_list or settings.ioc_list_path
    try:
        ioc_map = load_ioc_list(ioc_path)
    except IocError as exc:
        print(f"ioc error: {exc}", file=sys.stderr)
        return 1

    inputs = args.input or [settings.default_input]
    output = args.output or settings.default_output
    stats = ParseStats()
    events = []
    for input_path in inputs:
        events.extend(
            parse(
                input_path,
                args.format,
                csv_columns=settings.csv_columns,
                stats=stats,
            )
        )

    _, alerts = analyze(events, settings, ioc_map)
    write_json(alerts, output)
    print_table(alerts)
    elapsed = time.perf_counter() - started
    print(
        f"\nprocessed_events={len(events)} parse_errors={stats.skipped} "
        f"alerts={len(alerts)} elapsed_s={elapsed:.3f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
