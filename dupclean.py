#!/usr/bin/env python3

import argparse
import logging
import sys

from dup import find_files, duplicates, cleanup, keep

def cleanup_files(where, selected, dry_run=True, strict_walk=True):
    find_files(
        duplicates,
        where,
        action = cleanup(selected, clean_action=dry_run_clean if dry_run else None),
        strict_walk = strict_walk
    )

def dry_run_clean(x):
    print("would remove: {}".format(x))

def matching(cluster):
    print( "original :", cluster)
    cluster.pop()
    print( "resulting:", cluster)

    return cluster

def main():
    args_parser = argparse.ArgumentParser()
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs='+', help="Path where to look for duplicates.")
    parser.add_argument("-k", "--keep", action="append", required=True, help='Paths to keep.')
    parser.add_argument("-f", "--force", help='Force deletion.')
    parser.add_argument(
        "--non-strict",
        action="store_true",
        default=False,  # Strict mode by default
        help="Strict mode. Fails if there are nonreadable entries in the path."
    )
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

    strict_walk = not args.non_strict
    where = args.path
    protected = args.keep

    dry_run = True

    cleanup_files(
        where,
        selected = keep(*protected),
        dry_run = dry_run,
        strict_walk = strict_walk
    )

if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    main()
