#!/usr/bin/env python3

"""
Tool to verify C/C++ build configuration by checking the compile database.

Usage: see `cdb_check.py -h` for details.
"""

from dataclasses import dataclass
from pathlib import PurePath, Path
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
    directory: str = ''
    out_file: str = ''


OUT_FLAG = '-o'
PATH_REPLACEMENT = '[...]'


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
                    out_file=out_file,
                    directory=command['directory'].removesuffix('/'))


def load_cdb(file: str) -> List[CdbEntry]:
    """
    Open a CDB file and load to a list of CdbEntries.
    """
    with open(file) as f:
        commands = json.load(f)
        assert isinstance(commands, list)

        return [to_entry(c) for c in commands]


def replace_path_prefix(val: str, working_dir: str, base_dirs: List[str]) -> str:
    """
    Replace path prefix by the defined base dirs.
    """
    assert val
    assert working_dir and PurePath(working_dir).is_absolute()
    assert '' not in base_dirs
    assert '/' not in base_dirs
    assert all(PurePath(d).is_absolute() for d in base_dirs)

    if not PurePath(val).is_absolute():
        val = str(PurePath(working_dir).joinpath(val))

    for d in base_dirs:
        if val.startswith(d):
            return PATH_REPLACEMENT + val.removeprefix(d)
    return val


def normalize_base_dirs(base_dirs: List[str]) -> List[str]:
    """
    Convert relative paths of base dirs to absolute.
    """
    def convert(d: str) -> str:
        if PurePath(d).is_absolute():
            return d
        return str(Path.cwd().joinpath(d).resolve())
    return [convert(d) for d in base_dirs]


def normalize(entry: CdbEntry,
              base_dirs: List[str] = []) -> CdbEntry:
    """
    Normalize a CdbEntry with:
    - dropping 'output' and 'input' arguments of the command
    - TODO: remove path prefixes from all fields
    """

    base_dirs = normalize_base_dirs(base_dirs)

    def remove_opt_with_value(args: List[str], arg: str) -> List[str]:
        try:
            ix = args.index(arg)
            assert len(args) >= ix + 1
            return args[:ix] + args[ix+2:]
        except ValueError:
            return args

    args = remove_opt_with_value(entry.args, '-c')  # remove input argument
    args = remove_opt_with_value(args, OUT_FLAG)  # remove object file argument

    def remove_prefix(val: str) -> str:
        return replace_path_prefix(val, working_dir=entry.directory, base_dirs=base_dirs)

    def remove_substr(val: str) -> str:
        for b in base_dirs:
            if b in val:
                return val.replace(b, PATH_REPLACEMENT, 1)
        return val

    return CdbEntry(file=remove_prefix(entry.file),
                    directory=remove_prefix(entry.directory),
                    compiler=remove_prefix(entry.compiler),
                    args=[remove_substr(a) for a in args],
                    out_file=remove_prefix(entry.out_file))


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
    return any(entry.file.endswith(f) for f in cu_files)


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
            base_dirs: List[str] = [],
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
        base_dirs: List of path prefixes to drop
        dump: Dump the entries included in the check and return success

    Returns:
        bool: True in case of check passed.
    """

    print(f'Checking {cdb_file} ...')

    cdb = load_cdb(cdb_file)
    cdb = [normalize(e, base_dirs=base_dirs) for e in cdb]
    return check_cdb(cdb, cu_files=cu_files, flags=flags, dump=dump)


def load_config(file: str) -> Dict[str, List[str]]:
    """
    Load config file to a dictionary.
    """
    with open(file) as f:
        cfg = json.load(f)
        if not isinstance(cfg, dict):
            raise ValueError('Invalid config file')
        return cfg


def arg_parser() -> argparse.ArgumentParser:
    """
    Create CLI argument parser.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='Compile DB file (compile_commands.json)')
    parser.add_argument('-c', '--config', help='Config file')
    parser.add_argument('-u', '--compile-units', nargs='+', help='Compile units to check, default: all')
    parser.add_argument('-f', '--flags', nargs='+', help='Flags to check without \'-\' prefix')
    parser.add_argument('-b', '--base-dirs', nargs='+', help='Path prefixes to remove')
    parser.add_argument('-d', '--dump', action='store_true', help='Dump entries to check')
    return parser


def merge_config(cfg_from_file: Dict[str, List[str]],
                 cfg_from_args: argparse.Namespace) -> Dict[str, List[str]]:
    """
    Merge config file and CLI arguments to a consistent config set.
    """
    cfg = copy.copy(cfg_from_file)
    manual_args = {k: v for k, v in vars(cfg_from_args).items() if (
        v is not None) and (k not in ['config', 'input', 'dump'])}
    for k, v in manual_args.items():
        if k in cfg.keys():
            cfg[k] = list(set(cfg[k] + v))
        elif v is not None:
            cfg[k] = v
    cfg.setdefault('compile_units', [])
    cfg.setdefault('flags', [])
    cfg.setdefault('base_dirs', [])
    return cfg


def configure(args: argparse.Namespace) -> Dict[str, List[str]]:
    """
    Create configuration by loading config file on demand and applying CLI args.
    """
    cfg = load_config(args.config) if args.config else {}
    return merge_config(cfg, args)


def main():

    args = arg_parser().parse_args()
    cfg = configure(args)

    if process(args.input,
               cu_files=cfg['compile_units'],
               flags=cfg['flags'],
               base_dirs=cfg['base_dirs'],
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
    assert e.directory == '/path/to/build'
    assert e.compiler == RAW_ENTRY['command'].split()[0]
    assert e.args[0] == '-DOPT_1=1'
    assert e.args[-1] == 'src/file.c'
    assert e.out_file == 'out/file.c.o'


def test_replace_path_prefix():

    WORK_DIR = '/work'
    BASE_DIRS = ['/abs/path', '/work/path']

    assert replace_path_prefix(BASE_DIRS[0], WORK_DIR, BASE_DIRS) == PATH_REPLACEMENT
    assert replace_path_prefix(BASE_DIRS[1], WORK_DIR, BASE_DIRS) == PATH_REPLACEMENT

    assert replace_path_prefix('/abs/path/to/file', WORK_DIR, BASE_DIRS) == PATH_REPLACEMENT + '/to/file'
    assert replace_path_prefix('path/to/file', WORK_DIR, BASE_DIRS) == PATH_REPLACEMENT + '/to/file'
    assert replace_path_prefix('other/path/to/file', WORK_DIR, BASE_DIRS) == '/work/other/path/to/file'


def test_normalize_base_dirs():

    ABS = '/abs/path'
    REL = 'rel/path'
    cwd = str(Path.cwd())
    bd = normalize_base_dirs([ABS, REL])
    assert bd == [ABS, f'{cwd}/{REL}']


TEST_ENTRY = CdbEntry(file='/path/to/src/file.c',
                      directory='/path/to/build',
                      compiler='/path/to/compiler/gcc',
                      args=[
                          '-A1',
                          '-c',
                          'xxx',
                          '-A2',
                          '-o',
                          'yyy',
                          '-Irelative/include',
                          '-I/path/to/src/include',
                      ],
                      out_file='/path/to/build/file.c.o')


def test_normalize_drop_args():

    e = normalize(TEST_ENTRY)

    assert e.file == TEST_ENTRY.file
    assert e.compiler == TEST_ENTRY.compiler
    assert len(e.args) == len(TEST_ENTRY.args) - 4
    assert '-c' not in e.args
    assert 'yyy' not in e.args

    ENTRY_MISSING_OBJ = copy.copy(TEST_ENTRY)
    ENTRY_MISSING_OBJ.args = [a for a in TEST_ENTRY.args if a not in ['-o', 'yyy']]

    e2 = normalize(ENTRY_MISSING_OBJ)
    assert len(e2.args) == len(ENTRY_MISSING_OBJ.args) - 2
    assert '-c' not in e2.args
    assert 'xxx' not in e2.args


def test_normalize_trim_path():

    e = normalize(TEST_ENTRY, ['/path/to'])

    assert e.file.startswith(PATH_REPLACEMENT + '/src/')
    assert e.directory == PATH_REPLACEMENT + '/build'
    assert e.compiler.startswith(PATH_REPLACEMENT + '/compiler')
    assert e.out_file.startswith(PATH_REPLACEMENT + '/build/')

    assert e.args[-2] == '-Irelative/include'
    assert e.args[-1] == f'-I{PATH_REPLACEMENT}/src/include'


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
                        directory='/path/to/build',
                        compiler='/path/to/compiler/gcc',
                        args=['-A1', '-c', 'xxx', '-A2', '-o', 'yyy', '-I/path/to/src/include'])

TEST_ENTRY_3 = CdbEntry(file='/path/to/src/file3.c',
                        directory='/path/to/build',
                        compiler='/path/to/compiler/gcc',
                        args=['-A1', '-c', 'xxx', '-A3', '-o', 'yyy', '-I/path/to/src/include'])

TEST_CDB = [TEST_ENTRY, TEST_ENTRY_2, TEST_ENTRY_3]


def test_check_cdb():

    assert check_cdb(TEST_CDB, flags=['A1'])
    assert not check_cdb(TEST_CDB, flags=['A1', 'A2'])

    assert check_cdb(TEST_CDB, cu_files=[TEST_ENTRY_2.file], flags=['A1', 'A2'])
    assert not check_cdb(TEST_CDB, cu_files=[TEST_ENTRY_2.file], flags=['A1', 'A5'])


def test_merge_config_defaults():

    args = arg_parser().parse_args(['cc.json'])
    cfg = merge_config({}, args)

    assert cfg['compile_units'] == []
    assert cfg['flags'] == []
    assert cfg['base_dirs'] == []


FILE_1 = 'file1'
FILE_2 = 'file2'
FLAG_1 = 'flag1'
FLAG_2 = 'flag2'
DIR_1 = 'dir1'
DIR_2 = 'dir2'


def test_merge_config_no_file():

    args = arg_parser().parse_args(['cc.json', '-u', FILE_1, FILE_2, '-f', FLAG_1, FLAG_2, '-b', DIR_1, DIR_2])
    cfg = merge_config({}, args)

    assert cfg['compile_units'] == [FILE_1, FILE_2]
    assert cfg['flags'] == [FLAG_1, FLAG_2]
    assert cfg['base_dirs'] == [DIR_1, DIR_2]


def test_merge_config_from_file():

    CFG_FROM_FILE = {
        'compile_units': [FILE_1, FILE_2],
        'flags': [FLAG_1, FLAG_2],
        'base_dirs': [DIR_1, DIR_2]
    }

    args = arg_parser().parse_args(['cc.json'])
    cfg = merge_config(CFG_FROM_FILE, args)

    assert cfg['compile_units'] == [FILE_1, FILE_2]
    assert cfg['flags'] == [FLAG_1, FLAG_2]
    assert cfg['base_dirs'] == [DIR_1, DIR_2]


def test_merge_config_from_both():

    CFG_FROM_FILE = {
        'compile_units': [FILE_1],
        'flags': [FLAG_1],
        'base_dirs': [DIR_1]
    }

    args = arg_parser().parse_args(['cc.json', '-u', FILE_2, '-f', FLAG_1, FLAG_2, '-b', DIR_2])
    cfg = merge_config(CFG_FROM_FILE, args)

    assert all((v in cfg['compile_units']) for v in [FILE_1, FILE_2])
    assert all((v in cfg['flags']) for v in [FLAG_1, FLAG_2])
    assert all((v in cfg['base_dirs']) for v in [DIR_1, DIR_2])
