#!/usr/bin/env python3

"""
Tool to verify C/C++ build configuration by checking the compile database.

Usage: see `cdb_check.py -h` for details.
"""

from dataclasses import dataclass, field, fields, asdict
from pathlib import PurePath, Path
from typing import List, Dict, Union, Callable
import argparse
import copy
import json
import logging
import sys


__author__ = "Balazs Toth"
__email__ = "baltth@gmail.com"
__copyright__ = "Copyright 2025, Balazs Toth"
__license__ = "MIT"
__version__ = "0.2.0"


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

WILDCARD = '*'


def dedup(l: List) -> List:
    return list(dict.fromkeys(l).keys())


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
    logger = logging.getLogger()
    logger.debug(f'Checking {entry.file}')
    logger.debug(f'  expecting {" ".join(flags) if flags else "none"}')

    def flag_present(f: str) -> bool:
        if f.startswith('-'):
            return f in entry.args
        if f'-{f}' in entry.args:
            return True
        if f'--{f}' in entry.args:
            return True
        return False

    res = True
    for f in flags:
        if not flag_present(f):
            logger.warning(f'{entry.file}: missing flag \'{f}\'')
            res = False
    return res


def in_files(entry: Union[CdbEntry, str], cu_files: Union[List[str], str]) -> bool:
    """
    Check if an entry is associated to a _whitelisted_ file.
    The association is checked with pathlib.match() thus
    only non-recursive wildcard can be used.

    Returns:
        bool: True if the entry is whitelisted.
    """
    if isinstance(entry, CdbEntry):
        return in_files(entry.file, cu_files)
    if isinstance(cu_files, str):
        return in_files(entry, [cu_files])

    assert isinstance(entry, str)
    assert isinstance(cu_files, list)

    return any(PurePath(entry).match(f) for f in cu_files)


def in_libraries(entry: Union[CdbEntry, str], libraries: Union[List[str], str]) -> bool:
    """
    Check if an entry is associated to a _whitelisted_ library.
    The association is defined by the output file path of the
    compilation.

    Returns:
        bool: True if the entry is matching a whitelisted library.
    """
    if isinstance(entry, CdbEntry):
        return in_libraries(entry.out_file, libraries)
    if isinstance(libraries, str):
        return in_libraries(entry, [libraries])

    assert isinstance(entry, str)
    assert isinstance(libraries, list)

    def match(lib: str) -> bool:
        l = lib.removeprefix('/').removesuffix('/')
        return (f'/{l}/' in entry) or (f'CMakeFiles/{lib}.dir' in entry)
    return any(match(l) for l in libraries)


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


@dataclass
class Config:
    base_dirs: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    compile_units: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    verbose: bool = False
    flags_by_compiler: Dict[str, List[str]] = field(default_factory=dict)
    flags_by_library: Dict[str, List[str]] = field(default_factory=dict)
    flags_by_file: Dict[str, List[str]] = field(default_factory=dict)
    extra: Dict[str, Union[bool, str, List[str]]] = field(default_factory=dict)

    @staticmethod
    def from_dict(val: Dict, report_foreign_keys: bool = False) -> 'Config':
        return update_config(Config(), val, report_foreign_keys=report_foreign_keys)

    @staticmethod
    def keys():
        return [f.name for f in fields(Config) if f.name != 'extra']


def select_preset(presets: Dict[str, List[str]], predicate: Callable[[str], bool]) -> List[str]:
    """
    Select from preset list by predicate.

    Returns:
        List[str]: - Matching preset value, or
                   - preset[WILDCARD] if present, or
                   - empty
    """
    for k, v in presets.items():
        assert isinstance(v, list)
        if k != WILDCARD and predicate(k):
            return v
    return presets.get(WILDCARD, [])


def get_flags_by_compiler(cfg: Config, comp: str) -> List[str]:
    """
    Fetch compiler specific flags from the predefined set in configuration.

    Args:
        cfg: Config
        comp: Compiler property of a CdbEntry

    Returns:
        List[str]: Flags, the value of
                   - cfg.flags_by_compiler[name] if the configured name matches `comp`, or
                   - cfg.flags_by_compiler[WILDCARD] if present, or
                   - empty
    """
    comp_path = PurePath(comp.removeprefix(PATH_REPLACEMENT))
    return select_preset(cfg.flags_by_compiler, lambda x: comp_path.match(x))


def get_flags_by_library(cfg: Config, out_file: str) -> List[str]:
    """
    Fetch flags for the matching library predefined in the configuration.

    Args:
        cfg: Config
        out_file: Output file of a CdbEntry

    Returns:
        List[str]: Flags, the value of
                   - cfg.flags_by_library[name] if the configured name matches `out_file`, or
                   - cfg.flags_by_library[WILDCARD] if present, or
                   - empty
    """
    return select_preset(cfg.flags_by_library, lambda x: in_libraries(out_file, x))


def get_flags_by_file(cfg: Config, file: str) -> List[str]:
    """
    Fetch flags for the matching files predefined in the configuration.

    Args:
        cfg: Config
        file: Compile unit of a CdbEntry

    Returns:
        List[str]: Flags, the value of
                   - cfg.flags_by_file[name] if the configured name matches `file`, or
                   - cfg.flags_by_file[WILDCARD] if present, or
                   - empty
    """
    return select_preset(cfg.flags_by_file, lambda x: in_files(file, x))


def check_entry(entry: CdbEntry, cfg: Config) -> bool:
    """
    Perform flag check on a CdbEntry by flags fetched from the configuration.

    Returns:
        bool: True if all flags are present in the compilation.
    """

    flags = cfg.flags \
        + get_flags_by_compiler(cfg, entry.compiler) \
        + get_flags_by_library(cfg, entry.out_file) \
        + get_flags_by_file(cfg, entry.file)

    return check_flags(entry, dedup(flags))


def check_cdb(cdb: List[CdbEntry],
              cfg: Config,
              dump: bool = False) -> bool:
    """
    Perform check of flags on a CDB.

    Args:
        cdb: List of normalized CDB entries
        cfg: Configuration
        dump: Dump the entries included in the check and return success

    Returns:
        bool: True in case of check passed.
    """

    logger = logging.getLogger()

    filtered = False
    if cfg.libraries:
        filtered = True
        logger.debug('Filtered to libraries:')
        logger.debug(', '.join(cfg.libraries))
        cdb = [e for e in cdb if in_libraries(e, cfg.libraries)]

    if cfg.compile_units:
        filtered = True
        logger.debug('Filtered to files:')
        logger.debug(', '.join(cfg.compile_units))

        cdb = [e for e in cdb if in_files(e, cfg.compile_units)]

    qualifier = ' matching' if filtered else ''
    logger.info(f'Checking {len(cdb)}{qualifier} entries(s) ...')

    if dump:
        for e in cdb:
            dump_entry(e)
        return True

    all_ok = True
    for e in cdb:
        if not check_entry(e, cfg):
            all_ok = False

    return all_ok


def process(cdb_file: str,
            cfg: Config,
            dump: bool = False) -> bool:
    """
    Full processing of a CDB.
    - Load the CDB file
    - Perform normalization
    - Perform check of flags

    Args:
        cdb_file: Name of CDB file to load
        cu_files: List of files to check, defaults to check all.
        libraries: List of libraries to check, defaults to check all.
        flags: Compile flags to check
        base_dirs: List of path prefixes to drop
        dump: Dump the entries included in the check and return success

    Returns:
        bool: True in case of check passed.
    """

    logging.getLogger().debug(f'Checking {cdb_file} ...')

    cdb = load_cdb(cdb_file)
    cdb = [normalize(e, base_dirs=cfg.base_dirs) for e in cdb]
    return check_cdb(cdb, cfg=cfg, dump=dump)


def update_config(cfg: Config,
                  data_to_add: Dict,
                  report_foreign_keys: bool = False) -> Config:
    known_keys = [k for k in data_to_add.keys() if k in Config.keys()]
    foreign_keys = [k for k in data_to_add.keys() if k not in known_keys]

    def add(existing, val):
        if isinstance(existing, list):
            assert isinstance(val, list)
            return dedup(existing + val)
        elif isinstance(existing, dict):
            assert isinstance(val, dict)
            res = copy.copy(existing)
            for k, v in val.items():
                res[k] = add(res[k], v) if k in res.keys() else v
            return res
        elif isinstance(existing, bool):
            return existing or val
        else:
            return val

    updated = copy.copy(cfg)
    for k in known_keys:
        setattr(updated, k, add(getattr(updated, k), data_to_add[k]))

    for k in foreign_keys:
        updated.extra[k] = data_to_add[k]

    if report_foreign_keys and foreign_keys:
        keys_logged = ', '. join(foreign_keys)
        logging.getLogger().warning('Foreign keys in config file:')
        logging.getLogger().warning(f'  {keys_logged}')

    return updated


def load_config(file: str) -> Dict:
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
    parser.add_argument('-f', '--flags', nargs='+', help='Flags to check, passed without \'-\' prefix')
    parser.add_argument('-u', '--compile-units', nargs='+', help='Compile units to check, default: all')
    parser.add_argument('-l',
                        '--libraries',
                        nargs='+',
                        help='Logical \'libraries\' to check, default: all')
    parser.add_argument('-b', '--base-dirs', nargs='+',
                        help='Path prefixes to remove, either absolute or relative to $PWD')
    parser.add_argument('-d', '--dump', action='store_true', help='Dump entries to check')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    parser.description = "Tool to verify C/C++ build configuration. See README.md for details."
    parser.epilog = """
Notes about --libraries option:

Technically a libraries are associated by the output file path
(e.g. `build/CMakeFiles/lib.dir/file.c.o). A library contains all entries
whose output file contains the 'library_name' or 'CMakeFiles/library_name.dir' as parent.
Filtering by libraries is not equivalent to filtering by files - a file may be compiled
multiple times to different libraries with different setup.
"""

    return parser


def merge_config(cfg_from_file: Dict,
                 cfg_from_args: argparse.Namespace) -> Config:
    """
    Merge config file and CLI arguments to a consistent config set.
    """
    cfg = Config.from_dict(cfg_from_file, report_foreign_keys=True)
    cli_args = {k: v for k, v in vars(cfg_from_args).items() if v is not None}
    return update_config(cfg, cli_args)


def configure(args: argparse.Namespace) -> Config:
    """
    Create configuration by loading config file on demand and applying CLI args.
    """
    cfg = load_config(args.config) if args.config else {}
    return merge_config(cfg, args)


def configure_logging(verbose: bool):

    logging.basicConfig(
        format='[{levelname:.1}] {message}',
        style='{',
        level=logging.DEBUG,
        stream=sys.stderr,
    )

    logger = logging.getLogger()
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)


def main():

    args = arg_parser().parse_args()
    cfg = configure(args)

    configure_logging(args.dump or args.verbose)
    logger = logging.getLogger()

    if args.dump:
        logger.debug('Configuration:')
        print(asdict(cfg))

    if process(args.input,
               cfg=cfg,
               dump=args.dump):
        logger.info('OK')
    else:
        exit(1)


if __name__ == "__main__":
    main()


# Tests


def test_dedup():
    assert dedup([1, 1, 2, 1, 2, 3]) == [1, 2, 3]


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
                          '--sysroot=/path/to/toolchain/include',
                      ],
                      out_file='/path/to/build/CMakeFiles/lib.dir/src/file.c.o')


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

    assert e.args[-3] == '-Irelative/include'
    assert e.args[-2] == f'-I{PATH_REPLACEMENT}/src/include'
    assert e.args[-1] == f'--sysroot={PATH_REPLACEMENT}/toolchain/include'


def test_check_flags_no_prefix():

    assert check_flags(TEST_ENTRY, [])
    assert check_flags(TEST_ENTRY, ['A2'])
    assert check_flags(TEST_ENTRY, ['A1', 'A2'])

    assert not check_flags(TEST_ENTRY, ['A1', 'A7'])

    assert check_flags(TEST_ENTRY, ['sysroot=/path/to/toolchain/include'])


def test_check_flags_with_prefix():

    assert check_flags(TEST_ENTRY, ['-A1', '-A2'])

    assert check_flags(TEST_ENTRY, ['--sysroot=/path/to/toolchain/include'])
    assert not check_flags(TEST_ENTRY, ['-sysroot=/path/to/toolchain/include'])


def test_in_files():

    assert not in_files(TEST_ENTRY, [])
    assert not in_files(TEST_ENTRY, 'src/file4.c')

    assert in_files(TEST_ENTRY, 'src/file.c')
    assert in_files(TEST_ENTRY.file, 'src/file.c')

    assert in_files(TEST_ENTRY, ['src/file.c'])
    assert in_files(TEST_ENTRY, ['src/file.c', 'src/file2.c'])

    assert in_files(TEST_ENTRY, ['src/*'])
    assert in_files(TEST_ENTRY, ['*/src/*'])
    assert not in_files(TEST_ENTRY, ['src2/*'])

    assert in_files(TEST_ENTRY, ['src/*.c'])
    assert in_files(TEST_ENTRY, ['*.c'])
    assert not in_files(TEST_ENTRY, ['*.cpp'])


def test_in_libraries():

    assert not in_libraries(TEST_ENTRY, [])
    assert not in_libraries(TEST_ENTRY, 'some-lib-name')

    assert in_libraries(TEST_ENTRY, 'lib')
    assert in_libraries(TEST_ENTRY.out_file, 'lib')

    assert in_libraries(TEST_ENTRY, ['lib'])
    assert in_libraries(TEST_ENTRY, ['src'])
    assert in_libraries(TEST_ENTRY, ['lib', 'some-other-lib'])


def test_get_flags_by_compiler():

    def check(ref: List[str], flags: List[str]):
        assert all(f in flags for f in ref)
        assert len(ref) == len(flags)

    assert not get_flags_by_compiler(Config(), '')
    assert not get_flags_by_compiler(Config(), 'gcc-5')

    DEF = ['X', 'Y']

    CFG = Config(flags=DEF,
                 flags_by_compiler={
                     'gcc-5': ['A5', 'Y', 'B5', 'C5'],
                     'g*-8': ['A8', 'B8', 'C8'],
                     'bin/g*-11': ['D11', 'E11'],
                 })

    assert not get_flags_by_compiler(CFG, '')
    assert not get_flags_by_compiler(CFG, 'gcc-4')

    f = get_flags_by_compiler(CFG, 'gcc-5')
    check(CFG.flags_by_compiler['gcc-5'], f)

    f = get_flags_by_compiler(CFG, 'g++-8')
    check(CFG.flags_by_compiler['g*-8'], f)

    f = get_flags_by_compiler(CFG, '/usr/bin/gcc-11')
    check(CFG.flags_by_compiler['bin/g*-11'], f)

    CFG_WITH_DEFAULTS = update_config(CFG, {'flags_by_compiler': {'*': ['Fall']}})

    f = get_flags_by_compiler(CFG_WITH_DEFAULTS, 'g++-8')
    check(CFG_WITH_DEFAULTS.flags_by_compiler['g*-8'], f)
    assert 'Fall' not in f

    f = get_flags_by_compiler(CFG_WITH_DEFAULTS, 'gcc-4')
    check(CFG_WITH_DEFAULTS.flags_by_compiler['*'], f)


def test_get_flags_by_library():

    def check(ref: List[str], flags: List[str]):
        assert all(f in flags for f in ref)
        assert len(ref) == len(flags)

    assert not get_flags_by_library(Config(), TEST_ENTRY.out_file)

    DEF = ['X', 'Y']

    CFG = Config(flags=DEF,
                 flags_by_library={
                     'lib': ['A5', 'Y', 'B5', 'C5'],
                     '*': ['D11', 'E11'],
                 })

    f = get_flags_by_library(CFG, TEST_ENTRY.out_file)
    check(CFG.flags_by_library['lib'], f)

    f = get_flags_by_library(CFG, '/path/to/build/CMakeFiles/lib2.dir/src/file.c.o')
    check(CFG.flags_by_library[WILDCARD], f)


TEST_ENTRY_2 = CdbEntry(file='/path/to/src/file2.c',
                        directory='/path/to/build',
                        compiler='/path/to/compiler/gcc',
                        args=['-A1', '-A2', '-I/path/to/src/include'],
                        out_file='/path/to/build/CMakeFiles/lib.dir/src/file2.c.o')

TEST_ENTRY_3 = CdbEntry(file='/path/to/src/file3.c',
                        directory='/path/to/build',
                        compiler='/path/to/compiler/gcc',
                        args=['-A1', '-A3', '-A4', '-I/path/to/src/include'],
                        out_file='/path/to/build/CMakeFiles/lib2.dir/src/file3.c.o')


def test_check_entry():

    assert check_entry(TEST_ENTRY_2, cfg=Config(flags=['A1']))
    assert not check_entry(TEST_ENTRY_2, cfg=Config(flags=['A1', 'A3']))

    assert check_entry(TEST_ENTRY_2, cfg=Config(
        flags_by_compiler={'gcc': ['A1'], '*': ['fail']}))
    assert not check_entry(TEST_ENTRY_2, cfg=Config(
        flags_by_compiler={'g++': ['A1'], '*': ['fail']}))

    assert check_entry(TEST_ENTRY_2, cfg=Config(
        flags_by_library={'lib': ['A2'], '*': ['fail']}))
    assert not check_entry(TEST_ENTRY_3, cfg=Config(
        flags_by_library={'lib2': ['A2'], '*': ['fail']}))

    assert check_entry(TEST_ENTRY_2, cfg=Config(
        flags_by_file={'file*.c': ['A2'], '*': ['fail']}))
    assert not check_entry(TEST_ENTRY_2, cfg=Config(
        flags_by_file={'file*.c': ['A5'], '*': ['fail']}))


TEST_CDB = [TEST_ENTRY, TEST_ENTRY_2, TEST_ENTRY_3]


def test_check_cdb():

    assert check_cdb(TEST_CDB, cfg=Config(flags=['A1']))
    assert not check_cdb(TEST_CDB, cfg=Config(flags=['A1', 'A2']))

    assert check_cdb(TEST_CDB, cfg=Config(compile_units=[TEST_ENTRY_2.file],
                                          flags=['A1', 'A2']))
    assert not check_cdb(TEST_CDB, cfg=Config(compile_units=[TEST_ENTRY_2.file],
                                              flags=['A1', 'A5']))
    assert check_cdb(TEST_CDB, cfg=Config(libraries=['lib'],
                                          flags=['A1', 'A2']))

    assert check_cdb(TEST_CDB, cfg=Config(
        flags=['A1', 'I/path/to/src/include'],
        flags_by_library={
            'lib': ['A2'],
            'lib2': ['A3']
        },
        flags_by_file={
            "file3.c": ['A4']
        }
    ))


FILE_1 = 'file1'
FILE_2 = 'file2'
FLAG_1 = 'flag1'
FLAG_2 = 'flag2'
DIR_1 = 'dir1'
DIR_2 = 'dir2'


def test_update_config():

    assert update_config(Config(), {}) == Config()

    AD_HOC_DATA = {'a': True, 'b': ['b1', 'b1']}
    cfg = update_config(Config(), AD_HOC_DATA)
    assert cfg.extra == AD_HOC_DATA

    cfg = update_config(Config(), {'flags': [FLAG_1, FLAG_2]})
    assert cfg.flags == [FLAG_1, FLAG_2]
    assert not cfg.extra

    cfg = update_config(Config(base_dirs=[DIR_1]), {'base_dirs': [DIR_2]})
    assert cfg.base_dirs == [DIR_1, DIR_2]
    assert not cfg.extra


def test_merge_config_defaults():

    args = arg_parser().parse_args(['cc.json'])
    cfg = merge_config({}, args)

    assert cfg.compile_units == []
    assert cfg.flags == []
    assert cfg.base_dirs == []
    assert not cfg.verbose
    assert cfg.flags_by_compiler == {}


def test_merge_config_no_file():

    args = arg_parser().parse_args(['cc.json', '-u', FILE_1, FILE_2, '-f', FLAG_1, FLAG_2, '-b', DIR_1, DIR_2, '-v'])
    cfg = merge_config({}, args)

    assert cfg.compile_units == [FILE_1, FILE_2]
    assert cfg.flags == [FLAG_1, FLAG_2]
    assert cfg.base_dirs == [DIR_1, DIR_2]
    assert cfg.verbose


def test_merge_config_from_file():

    CFG_FROM_FILE = {
        'compile_units': [FILE_1, FILE_2],
        'flags': [FLAG_1, FLAG_2],
        'base_dirs': [DIR_1, DIR_2],
        'verbose': True
    }

    args = arg_parser().parse_args(['cc.json'])
    cfg = merge_config(CFG_FROM_FILE, args)

    assert cfg.compile_units == [FILE_1, FILE_2]
    assert cfg.flags == [FLAG_1, FLAG_2]
    assert cfg.base_dirs == [DIR_1, DIR_2]
    assert cfg.verbose


def test_merge_config_from_both():

    CFG_FROM_FILE = {
        'compile_units': [FILE_1],
        'flags': [FLAG_1],
        'base_dirs': [DIR_1],
        'verbose': False
    }

    args = arg_parser().parse_args(['cc.json', '-u', FILE_2, '-f', FLAG_1, FLAG_2, '-b', DIR_2, '-v'])
    cfg = merge_config(CFG_FROM_FILE, args)

    assert cfg.compile_units == [FILE_1, FILE_2]
    assert cfg.flags == [FLAG_1, FLAG_2]
    assert cfg.base_dirs == [DIR_1, DIR_2]
    assert cfg.verbose


def test_merge_config_extra_fields():

    args = arg_parser().parse_args(['cc.json'])
    cfg = merge_config({}, args)
    assert cfg.extra['input'] == 'cc.json'
