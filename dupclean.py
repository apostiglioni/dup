#!/usr/bin/env python3

import argparse
import logging
import sys

from dup import find_files, duplicates, cleanup, exclude, remove

def cleanup_files(where, selector, dry_run=True):
    find_files(
        duplicates,
        where,
        action = cleanup(selector, clean_action=dry_run_clean if dry_run else remove),
    )

def dry_run_clean(x):
    print("would remove: {}".format(x))

def main():
    parser = argparse.ArgumentParser(description="Remove duplicate files.")
    parser.add_argument("path", nargs='+', help="Path where to look for duplicates.")
    parser.add_argument("-k", "--keep", action="append", required=True, help='Paths to keep.')
    parser.add_argument("-f", "--force", action="store_true", help='Force deletion.') # Dry run by default
#  parser.add_argument(
#    "-v",
#    "--verbosity",
#    help="Verbosity level (default: WARN)",
#    default='WARN',
#    choices=['DEBUG','INFO','WARN','ERROR','CRITICAL'],
#    type=lambda level: level.upper()
#  )
#
#  logging.basicConfig(
#    level=args.verbosity,
#    format=args.log_format,
#    filename=args.log
#  )

    args = parser.parse_args()

    where = args.path
    protected = args.keep

    dry_run = not args.force

    cleanup_files(
        where,
        selector = exclude(*protected),
        dry_run = dry_run
    )

if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    main()
