#!/usr/bin/env python3

"""
Tool to verify C/C++ build configuration by checking the compile database.

Usage: see `cdb_check.py -h` for details.
"""

from dataclasses import dataclass, field
from typing import List, Dict
import argparse
import copy
import json
import sys


__author__ = "Balazs Toth"
__email__ = "baltth@gmail.com"
__copyright__ = "Copyright 2025, Balazs Toth"
__license__ = "MIT"
__version__ = "0.0.1"


@dataclass
class CdbEntry:
    """
    Internal model of a single compilation.
    """
    file: str
    compiler: str
    args: List[str]
    out_file: str = ''


OUT_FLAG = '-o'


def to_entry(command: Dict[str, str]) -> CdbEntry:
    """
    Convert a dictionary loaded from a CDB to a CdbEntry.
    Compiler, compile argument and object file properties are split from the 'command' field.
    """
    cmd = command['command'].split()
    assert len(cmd) >= 2

    try:
        ix = cmd.index(OUT_FLAG)
        out_file = cmd[ix + 1]
    except:
        out_file = ''
        assert False

    return CdbEntry(file=command['file'],
                    compiler=cmd[0],
                    args=cmd[1:],
                    out_file=out_file)


def load_cdb(file: str) -> List[CdbEntry]:
    """
    Open a CDB file and load to a list of CdbEntries.
    """
    with open(file) as f:
        commands = json.load(f)
        assert isinstance(commands, list)

        return [to_entry(c) for c in commands]


def normalize(entry: CdbEntry) -> CdbEntry:
    """
    Normalize a CdbEntry with:
    - dropping 'output' and 'input' arguments of the command
    - TODO: remove path prefixes from all fields
    """
    def remove_with_value(args: List[str], arg: str) -> List[str]:
        try:
            ix = args.index(arg)
            assert len(args) >= ix + 1
            return args[:ix] + args[ix+2:]
        except ValueError:
            return args

    args = remove_with_value(entry.args, '-c')  # remove input argument
    args = remove_with_value(args, OUT_FLAG)  # remove object file argument

    return CdbEntry(file=entry.file,
                    compiler=entry.compiler,
                    args=args,
                    out_file=entry.out_file)


def check_flags(entry: CdbEntry, flags: List[str]) -> bool:
    """
    Check if a set of compile flags is present in a CdbEntry,
    additionally log errors to stderr.

    Returns:
        bool: True if all flags are present in the compilation.

    TODO:
        - support MSVC arguments
    """
    res = True
    for f in flags:
        if f'-{f}' not in entry.args:
            print(f'{entry.file}: missing flag \'{f}\'', file=sys.stderr)
            res = False
    return res


def in_files(entry: CdbEntry, cu_files: List[str]) -> bool:
    """
    Check if an entry is associated to a _whitelisted_ file.
    The association is an 'ends with' match for now.

    Returns:
        bool: True if the entry is whitelisted.

    TODO:
        - add simple globbing
    """
    return any([entry.file.endswith(f) for f in cu_files])


def dump_entry(e: CdbEntry):
    """
    Dump a single CdbEntry to stdout.
    """
    ARG_PREFIX = '    '
    print(e.file)
    print(f'  compiled with {e.compiler}')
    if e.out_file:
        print(f'  to file {e.out_file}')
    if e.args:
        print(f'  with args')
        print(ARG_PREFIX + ('\n' + ARG_PREFIX).join(e.args))


def check_cdb(cdb: List[CdbEntry],
              cu_files: List[str] = [],
              flags: List[str] = [],
              dump: bool = False) -> bool:
    """
    Perform check of flags on a CDB.

    Args:
        cdb: List of normalized CDB entries
        cu_files: List of files to check, defaults to check all.
        flags: Compile flags to check
        dump: Dump the entries included in the check and return success

    Returns:
        bool: True in case of check passed.
    """

    all_ok = True

    if cu_files:
        print('Filtered to files:')
        print(', '.join(cu_files))

        cdb = [e for e in cdb if in_files(e, cu_files)]

    for e in cdb:
        if dump:
            dump_entry(e)
        else:
            if not check_flags(e, flags):
                all_ok = False

    return all_ok


def process(cdb_file: str,
            cu_files: List[str] = [],
            flags: List[str] = [],
            dump: bool = False) -> bool:
    """
    Full processing of a CDB.
    - Load the CDB file
    - Perform normalization
    - Perform check of flags

    Args:
        cdb_file: Name of CDB file to load
        cu_files: List of files to check, defaults to check all.
        flags: Compile flags to check
        dump: Dump the entries included in the check and return success

    Returns:
        bool: True in case of check passed.
    """

    print(f'Checking {cdb_file} ...')

    cdb = load_cdb(cdb_file)
    cdb = [normalize(e) for e in cdb]
    return check_cdb(cdb, cu_files=cu_files, flags=flags, dump=dump)


def load_config(file: str) -> Dict[str, List[str]]:
    with open(file) as f:
        cfg = json.load(f)
        if not isinstance(cfg, dict):
            raise ValueError('Invalid config file')
        return cfg


def merge_config(cfg_from_file: Dict[str, List[str]],
                 cfg_from_args: argparse.Namespace) -> Dict[str, List[str]]:
    cfg = copy.copy(cfg_from_file)
    manual_args = {k: v for k, v in vars(cfg_from_args).items() if (
        v is not None) and (k not in ['config', 'input', 'dump'])}
    for k, v in manual_args.items():
        if k in cfg.keys():
            cfg[k] += v
        else:
            cfg[k] = v
    return cfg


def arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='Compile DB file (compile_commands.json)')
    parser.add_argument('-c', '--config', help='Config file')
    parser.add_argument('-u', '--compile-units', nargs='+', help='Compile units to check, default: all')
    parser.add_argument('-f', '--flags', nargs='+', help='Flags to check without \'-\' prefix')
    parser.add_argument('-d', '--dump', action='store_true', help='Dump entries to check')
    return parser


def main():

    args = arg_parser().parse_args()

    if args.config:
        cfg = load_config(args.config)
    else:
        cfg = {}

    cfg = merge_config(cfg, args)

    if process(args.input,
               cu_files=cfg.get('compile_units', []),
               flags=cfg.get('flags', []),
               dump=args.dump):
        print('OK')
    else:
        exit(1)


if __name__ == "__main__":
    main()


# Tests

def test_to_entry():

    RAW_ENTRY = {
        "directory": "/path/to/build",
        "command": "/usr/bin/gcc-8 -DOPT_1=1 -DOPT_2 -DOPT_3=\\\"quoted\\\" -I/path/to_inc -o out/file.c.o -c src/file.c",
        "file": "/path/to/src/src.c"
    }

    e = to_entry(RAW_ENTRY)

    assert e.file == RAW_ENTRY['file']
    assert e.compiler == RAW_ENTRY['command'].split()[0]
    assert e.args[0] == '-DOPT_1=1'
    assert e.args[-1] == 'src/file.c'
    assert e.out_file == 'out/file.c.o'


TEST_ENTRY = CdbEntry(file='/path/to/src/file.c',
                      compiler='/path/to/compiler/gcc',
                      args=['-A1', '-c', 'xxx', '-A2', '-o', 'yyy', '-I/path/to/src/include'],
                      out_file='/path/to/build/file.c.o')


def test_normalize():

    e = normalize(TEST_ENTRY)

    assert e.file == TEST_ENTRY.file
    assert e.compiler == TEST_ENTRY.compiler
    assert len(e.args) == len(TEST_ENTRY.args) - 4
    assert '-c' not in e.args
    assert 'yyy' not in e.args

    ENTRY_MISSING_OBJ = CdbEntry(file=TEST_ENTRY.file,
                                 compiler=TEST_ENTRY.compiler,
                                 args=[a for a in TEST_ENTRY.args if a not in ['-o', 'yyy']])

    e2 = normalize(ENTRY_MISSING_OBJ)
    assert len(e2.args) == len(ENTRY_MISSING_OBJ.args) - 2
    assert '-c' not in e2.args
    assert 'xxx' not in e2.args


def test_check_flags():

    assert check_flags(TEST_ENTRY, [])
    assert check_flags(TEST_ENTRY, ['A2'])
    assert check_flags(TEST_ENTRY, ['A1', 'A2'])

    assert not check_flags(TEST_ENTRY, ['A1', 'A7'])


def test_in_files():

    assert not in_files(TEST_ENTRY, [])
    assert not in_files(TEST_ENTRY, ['src/file4.c'])

    assert in_files(TEST_ENTRY, ['src/file.c'])
    assert in_files(TEST_ENTRY, ['src/file.c', 'src/file2.c'])


TEST_ENTRY_2 = CdbEntry(file='/path/to/src/file2.c',
                        compiler='/path/to/compiler/gcc',
                        args=['-A1', '-c', 'xxx', '-A2', '-o', 'yyy', '-I/path/to/src/include'])

TEST_ENTRY_3 = CdbEntry(file='/path/to/src/file3.c',
                        compiler='/path/to/compiler/gcc',
                        args=['-A1', '-c', 'xxx', '-A3', '-o', 'yyy', '-I/path/to/src/include'])

TEST_CDB = [TEST_ENTRY, TEST_ENTRY_2, TEST_ENTRY_3]


def test_check_cdb():

    assert check_cdb(TEST_CDB, flags=['A1'])
    assert not check_cdb(TEST_CDB, flags=['A1', 'A2'])

    assert check_cdb(TEST_CDB, cu_files=[TEST_ENTRY_2.file], flags=['A1', 'A2'])
    assert not check_cdb(TEST_CDB, cu_files=[TEST_ENTRY_2.file], flags=['A1', 'A5'])
