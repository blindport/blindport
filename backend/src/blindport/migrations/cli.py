"""Command-line interface for Blindport database migrations."""

from __future__ import annotations

import argparse
import sys

from blindport.db import engine

from . import database_revisions, downgrade_database, upgrade_database


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blindport-migrate")
    commands = parser.add_subparsers(dest="command", required=True)

    upgrade = commands.add_parser("upgrade", help="upgrade the database")
    upgrade.add_argument("revision", nargs="?", default="head")

    current = commands.add_parser("current", help="show current and head revisions")
    current.add_argument(
        "--check",
        action="store_true",
        help="exit unsuccessfully unless the database is at head",
    )

    downgrade = commands.add_parser("downgrade", help="downgrade the database")
    downgrade.add_argument("revision")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "upgrade":
        upgrade_database(engine, args.revision)
        current, head = database_revisions(engine)
        print(f"current: {current}")
        print(f"head: {head}")
        return 0
    if args.command == "downgrade":
        downgrade_database(engine, args.revision)
        current, head = database_revisions(engine)
        print(f"current: {current or 'base'}")
        print(f"head: {head}")
        return 0

    current, head = database_revisions(engine)
    print(f"current: {current or 'unversioned'}")
    print(f"head: {head}")
    if args.check and current != head:
        print(
            f"error: database revision is {current or 'unversioned'}, "
            f"expected migration head {head}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
