#!/usr/bin/env python3

import argparse

from colltools import for_each
from dup import find_files, uniques, duplicates

def print_uniques(cluster):
    for file in cluster:
        print(file)

def print_duplicates(cluster):
    print('------')
    for file in cluster:
        print(file)

def main():
    args_parser = argparse.ArgumentParser()
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs='+', help="Path where to look for duplicates")
    parser.add_argument("-u", "--uniques", action="store_true", help="Find unique files")
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

    which = uniques if args.uniques else duplicates
    action = print_uniques if args.uniques else print_duplicates
    where = args.path

    find_files(which, where, action)


if __name__ == "__main__":
    main()

# escenario scan devuelve 1 si hay warnings
