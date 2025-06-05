#!/usr/bin/env python3

"""
Tool to verify C/C++ build configuration by checking the compile database.

Usage: see `cdb_check.py -h` for details.
"""

from dataclasses import dataclass, field, fields, asdict
from pathlib import PurePath, Path
from typing import List, Dict, Union, Tuple, Callable
from shlex import split
import argparse
import copy
import json
import logging
import re
import sys


__author__ = "Balazs Toth"
__email__ = "baltth@gmail.com"
__copyright__ = "Copyright 2025, Balazs Toth"
__license__ = "MIT"
__version__ = "0.3.0"


def path_wildcards_to_regex(path: str) -> str:
    """
    Transform a string with wildcards to a regex.
    As `pathlib.PurePath.full_match()` is not available with python 3.12,
    we're emulating its pattern language with regex.
    See https://docs.python.org/3/library/pathlib.html#pathlib-pattern-language

    Limitations:
    - one character match of `/` is not supported, i.e. `[ab/]`
    - trailing '/' is ignored
    """

    NON_SEP = '[^/]'

    REC_WILDCARD = '**'
    REC_WILDCARD_PATTERN = '(/.+)?'
    REC_WILDCARD_PATTERN_NO_SLASH = '(.+)?'

    WILDCARD = '*'
    WILDCARD_PATTERN = f'{NON_SEP}*'
    WILDCARD_DIR_PATTERN = f'{NON_SEP}+'

    ONE_CHAR = '?'
    ONE_CHAR_PATTERN = NON_SEP

    NOT_IN_CHARS_PATTERN = r'^(\[!(.+)\])'
    IN_CHARS_PATTERN = r'^(\[(.+)\])'

    assert not re.search(r'\[[^]]*/[^]]*\]', path)  # contains no `/` between `[]`
    path = path.removesuffix('/')

    # Sequential processing for a path segment
    def consume(p: str) -> Tuple[str, str]:
        assert REC_WILDCARD not in p
        # wildcard as segment part
        if p.startswith(WILDCARD):
            return WILDCARD_PATTERN, p.removeprefix(WILDCARD)
        # any character
        if p.startswith(ONE_CHAR):
            return ONE_CHAR_PATTERN, p.removeprefix(ONE_CHAR)
        # one char not from set
        r = re.match(NOT_IN_CHARS_PATTERN, p)
        if r:
            chars = r.group(2)
            return f'[^{re.escape(chars)}]', p.removeprefix(r.group(1))
        # one char from set
        r = re.match(IN_CHARS_PATTERN, p)
        if r:
            chars = r.group(2)
            return f'[{re.escape(chars)}]', p.removeprefix(r.group(1))
        # pass other
        return re.escape(p[0]), p[1:]

    # Process path by segments
    path_parts = path.split('/')
    regex_parts: List[str] = []
    for part in path_parts:
        if part == REC_WILDCARD:    # segment is recursive wildcard
            regex_parts.append(REC_WILDCARD_PATTERN)
        elif part == WILDCARD:      # segment is wildcard
            regex_parts.append(WILDCARD_DIR_PATTERN)
        else:                       # process segment sequentially
            regex = ''
            while part:
                r, part = consume(part)
                regex += r
            regex_parts.append(regex)

    # Join segments and post-process
    r = '/'.join(regex_parts)
    # - remove extra `/` before recursive wildcards, added by join()
    r = r.replace('/' + REC_WILDCARD_PATTERN, REC_WILDCARD_PATTERN)
    # - remove `/` of leading recursive wildcard
    if r.startswith(REC_WILDCARD_PATTERN):
        r = r.replace(REC_WILDCARD_PATTERN, REC_WILDCARD_PATTERN_NO_SLASH, 1)
    return r


def match_path(ref: str, path: str) -> bool:
    '''
    Match path like either by
    - a method like `pathlib` _pattern language, or
    - a full match on the last path segment

    The leading _path replacement pattern_ of the check path is ignored.

    As that function is not available with python 3.12,
    we're emulating its pattern language with regex.
    See https://docs.python.org/3/library/pathlib.html#pathlib-pattern-language

    Limitations:
    - one character match of `/` is not supported, i.e. `[ab/]`
    - trailing '/' of ref is ignored
    '''
    if not ref or not path:
        return False

    # '[...]/' or `[...]` trimmed, a normal leading `/` is kept.
    p = path.removeprefix(PATH_REPLACEMENT + '/').removeprefix(PATH_REPLACEMENT)
    if '/' not in ref and p.split('/')[-1] == ref:
        return True
    m = re.fullmatch(path_wildcards_to_regex(ref), p)
    return m is not None


@dataclass
class CdbEntry:
    """
    Internal model of a single compilation.
    """
    file: str
    compiler: str
    args: List[str]
    orig_args: List[str] = field(default_factory=list)
    directory: str = ''
    out_file: str = ''


OUT_FLAG = '-o'
PATH_REPLACEMENT = '[...]'
PATH_REPLACEMENT_IN_REGEX = re.escape(PATH_REPLACEMENT)

WILDCARD = '*'

FLAG_REGEX_PREFIX = '#'
FLAG_BANNED_PREFIX = '!'


def dedup(l: List) -> List:
    return list(dict.fromkeys(l).keys())


def to_entry(command: Dict[str, str]) -> CdbEntry:
    """
    Convert a dictionary loaded from a CDB to a CdbEntry.
    Compiler, compile argument and object file properties are split from the 'command' field.
    """
    cmd = split(command['command'])
    assert len(cmd) >= 2

    try:
        ix = cmd.index(OUT_FLAG)
        out_file = cmd[ix + 1]
    except Exception:
        out_file = ''
        assert False
    args = cmd[1:]
    return CdbEntry(file=command['file'],
                    compiler=cmd[0],
                    args=args,
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


def join_opt_pairs(args: List[str]) -> List[str]:
    if len(args) < 2:
        return args
    if args[1].startswith('-'):
        return [args[0]] + join_opt_pairs(args[1:])
    front_joint = [' '.join(args[0:2])] + args[2:]
    return join_opt_pairs(front_joint)


def normalize(entry: CdbEntry,
              base_dirs: List[str] = []) -> CdbEntry:
    """
    Normalize a CdbEntry with:
    - dropping 'output' and 'input' arguments of the command
    - removing path prefixes from all fields
    """

    base_dirs = normalize_base_dirs(base_dirs)

    args = join_opt_pairs(entry.args)

    def remove_opt_with_value(args: List[str], arg: str) -> List[str]:
        return [a for a in args if not a.startswith(f'{arg} ')]

    args = remove_opt_with_value(args, '-c')  # remove input argument
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
                    orig_args=args,
                    out_file=remove_prefix(entry.out_file))


def is_disabler(flag: str) -> bool:
    return len(flag) > 5 and flag[:5].endswith('no-')


def make_enabler(flag: str) -> str:
    return flag[:2] + flag[5:] if is_disabler(flag) else flag


def collect_flags_by_keys(flags: List[str]) -> Dict[str, List[str]]:
    """
    Collect flags by the logical option they represent.
    """
    def key_of(f: str):
        m = re.search(r'^(--?[a-zA-Z][a-zA-Z0-9_-]*=)', f)
        key = f'{m.group(1)}...' if m else f
        if key.startswith('-O'):
            return '-O...'
        if re.search(r'^-g[\d]?$', key):
            return '-g...'
        return make_enabler(key)

    res: Dict[str, List[str]] = {}
    for f in flags:
        key = key_of(f)
        if key in res.keys():
            res[key].append(f)
        else:
            res[key] = [f]
    return res


def get_duplicates(flags: List[str]) -> int:
    return len(flags) - len(set(flags))


def has_contradiction(flags: List[str]) -> bool:
    if len(flags) < 2:
        return False
    enablers: List[str] = []
    disablers: List[str] = []
    for f in flags:
        if is_disabler(f):
            disablers.append(make_enabler(f))
        else:
            enablers.append(f)
    return not set(enablers).isdisjoint(set(disablers))


def check_consistency_of_collected(flags_by_keys: Dict[str, List[str]]) -> Tuple[List[str], List[str]]:

    contra: List[str] = []
    duplicates: List[str] = []
    for k, v in flags_by_keys.items():
        dup = get_duplicates(v)
        if has_contradiction(v):
            contra.append(k)
        elif dup > 0:
            duplicates.append(k)
    return contra, duplicates


def check_consistency(entry: CdbEntry) -> bool:

    flags_by_keys = collect_flags_by_keys(entry.orig_args)
    contra, dup = check_consistency_of_collected(flags_by_keys)
    for f in contra:
        logging.getLogger().warning(f'{entry.file}: contradicting options of {f}')
    for f in dup:
        logging.getLogger().warning(f'{entry.file}: duplicate(s) found of {f}')
    return not contra and not dup


def check_flag(flag: str, flag_set: List[str]) -> bool:
    """
    Check if a flag is present or not present in a flag set.

    - A flag starting with `!` is expected to be not in the set.
    - A flag starting with `#` is matched as regex
    - A flag starting with `-` is expected as-is
    - Otherwise the flag is checked if present prefixed with `-` or `--`

    Returns:
        bool: True if the flag meets the expectations.

    TODO:
        - support MSVC arguments
    """
    if flag.startswith(FLAG_BANNED_PREFIX):
        return not check_flag(flag.removeprefix(FLAG_BANNED_PREFIX), flag_set)
    if flag.startswith(FLAG_REGEX_PREFIX):
        normalized_flag = flag.removeprefix(FLAG_REGEX_PREFIX).replace(PATH_REPLACEMENT, PATH_REPLACEMENT_IN_REGEX)
        return any(re.search(normalized_flag, a) for a in flag_set)
    if flag.startswith('-'):
        return flag in flag_set
    if f'-{flag}' in flag_set:
        return True
    if f'--{flag}' in flag_set:
        return True
    return False


def check_flags(entry: CdbEntry, flags: List[str]) -> bool:
    """
    Check if a set of compile flags is present (or not) in a CdbEntry,
    additionally log errors to stderr.

    Returns:
        bool: True if all flags meet the expectations.

    TODO:
        - support MSVC arguments
    """

    res = True
    for f in flags:
        if not check_flag(f, entry.args):
            logging.getLogger().warning(f'{entry.file}: missing flag \'{f}\'')
            res = False
    if res:
        logging.getLogger().debug('All flags found')
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

    return any(match_path(ref=f, path=entry) for f in cu_files)


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
        assert '**' not in lib
        lib_pattern = path_wildcards_to_regex(lib.removeprefix('/').removesuffix('/'))
        direct_pattern = f'/{lib_pattern}/'
        cmake_pattern = f'/CMakeFiles/{lib_pattern}.dir/'
        return re.search(cmake_pattern, entry) is not None or re.search(direct_pattern, entry) is not None
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
        print('  with args')
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
            logging.getLogger().debug(f'  ... matching: {k}')
            return v
    if WILDCARD in presets:
        logging.getLogger().debug(f'  ... matching: {WILDCARD}')
        return presets[WILDCARD]
    return []


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
    logging.getLogger().debug('Checking for flag preset by compiler ...')
    return select_preset(cfg.flags_by_compiler, lambda x: match_path(ref=x, path=comp))


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
    logging.getLogger().debug('Checking for flag preset by library ...')
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
    logging.getLogger().debug('Checking for flag preset by file name ...')
    return select_preset(cfg.flags_by_file, lambda x: in_files(file, x))


def check_entry(entry: CdbEntry, cfg: Config, dump: bool = False) -> bool:
    """
    Perform flag check on a CdbEntry by flags fetched from the configuration.

    Returns:
        bool: True if all flags are present in the compilation.
    """

    logger = logging.getLogger()
    logger.debug(f'Entry {entry.file} ...')

    to_check = cfg.flags \
        + get_flags_by_compiler(cfg, entry.compiler) \
        + get_flags_by_library(cfg, entry.out_file) \
        + get_flags_by_file(cfg, entry.file)
    to_check = dedup(to_check)

    if dump:
        dump_entry(entry)
        return True

    logger.debug(f'Expecting {" ".join(to_check) if to_check else "none"}')

    check_consistency(entry)

    return check_flags(entry, to_check)


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

    if not cdb:
        logger.warning('No compilation to check.')
        logger.warning('Please verify the effective configuration using the -v/--verbose argument.')
        return False

    all_ok = True
    for e in cdb:
        if not check_entry(e, cfg, dump=dump):
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
    parser.description = "Tool to verify C/C++ build configuration. See README.md for details."
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


def configure_logging(use_debug: bool):

    class StdoutFilter(logging.Filter):
        def filter(self, record):
            return record.levelno < logging.WARNING

    stdout_handler = logging.StreamHandler(sys.stdout)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stdout_handler.addFilter(StdoutFilter())
    stdout_handler.setLevel(logging.DEBUG)
    stderr_handler.setLevel(logging.WARNING)

    logger = logging.getLogger()
    logger.addHandler(stdout_handler)
    logger.addHandler(stderr_handler)

    if use_debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)


def main():

    args = arg_parser().parse_args()
    cfg = configure(args)

    configure_logging(args.verbose)
    logger = logging.getLogger()

    if args.verbose:
        logger.debug('cdb-check - running in verbose mode')
        logger.debug('Configuration:')
        logger.debug(asdict(cfg))

    if process(args.input,
               cfg=cfg,
               dump=args.dump):
        logger.info('OK')
    else:
        exit(1)


if __name__ == "__main__":
    main()
