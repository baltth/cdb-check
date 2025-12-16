#!/usr/bin/env python3

"""
Tool to verify C/C++ build configuration by checking the compile database.

Usage: see `cdb_check.py -h` for details.
"""

from dataclasses import dataclass, field, fields
from enum import IntEnum
from pathlib import PurePath, Path
import pprint
from typing import List, Dict, Set, Union, Tuple, Callable, Optional, Any
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
__version__ = "0.5.1"


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
    REC_WILDCARD_PATTERN_LEADING = '(.*/)?'
    REC_WILDCARD_PATTERN_STANDALONE = '.+'

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
    if r.startswith(REC_WILDCARD_PATTERN + '/'):
        r = r.replace(REC_WILDCARD_PATTERN + '/', REC_WILDCARD_PATTERN_LEADING, 1)
    elif r == REC_WILDCARD_PATTERN:
        r = REC_WILDCARD_PATTERN_STANDALONE
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

PRESET_REF_PREFIX = '$'

LOG_SEPARATOR = "\n--------"


class ConsistencyLevel(IntEnum):
    NONE = 0
    CONTRADICTING = 1
    INEFFECTIVE = 2
    ALL = 3


def dedup(l: List) -> List:
    # The single line method with dict.fromkeys(l) does not work with List[Dict]...
    res = []
    for item in l:
        if item not in res:
            res.append(item)
    return res


def to_entry(command: Dict[str, Union[str, List[str]]]) -> CdbEntry:
    """
    Convert a dictionary loaded from a CDB to a CdbEntry.
    Compiler, compile argument and object file properties are split from
    'command' or 'arguments' field.
    """

    assert isinstance(command['file'], str)
    assert isinstance(command['directory'], str)

    if 'command' in command.keys():
        assert isinstance(command['command'], str)
        cmd = split(command['command'])
    else:
        assert 'arguments' in command.keys()
        assert isinstance(command['arguments'], list)
        cmd = command['arguments']

    assert len(cmd) >= 2

    try:
        ix = cmd.index(OUT_FLAG)
        out_file = cmd[ix + 1]
    except Exception:
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
    """
    Join corresponding argument pairs.
    - `['-a', '-b', 'b_value', '-c']` -> `['-a', '-b b_value', '-c']`
    """

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


def make_enabler(flag: str) -> str:
    """
    Get 'enabler' version of a 'disabler' flag or return the original.
    - `-Wno-unused` -> `-Wunused`
    - `-Werror` -> `-Werror`
    """
    m = re.match(r'^(-[a-zA-Z])no-(.+)', flag)
    if m:
        return f'{m.group(1)}{m.group(2)}'
    return flag


MULTI_FLAGS = [
    '-I',
    '-idirafter',
    '-imacros ',
    '-imultilib ',
    '-iplugin=',
    '-iprefix ',
    '-iquote ',
    '-isysroot ',
    '-isystem ',
    '-iwithprefix ',
    '-iwithprefixbefore ',
    '--embed-dir=',
    '-L',
    '-l'
]

GENERAL_W_FLAGS = [
    '-Wall',
    '-Wextra',
    '-Werror',
]


def match_multi_flag(flag: str) -> str:
    """
    Check if a flag is a 'multi flag', i.e.
    may be applied multiple times.

    Returns:
        str: the flag itself if multi-flag else empty
    """
    for f in MULTI_FLAGS:
        if flag.startswith(f):
            return flag
    return ''


def is_multi_flag(flag: str) -> bool:
    return bool(match_multi_flag(flag))


WERROR_FLAGS = ['-Werror', '-Wno-error']
WERROR_OPT_FLAGS = [f'{f}=' for f in WERROR_FLAGS]


def werror_enabled(flags: List[str]) -> bool:
    """
    Check if '-Werror' is enables effectively,
    i.e. not turned off by a -Wno-error switch later.
    """
    opts = [f for f in flags if f in WERROR_FLAGS]
    if opts:
        return opts[-1] == '-Werror'
    return False


def match_switch_flag(flag: str) -> str:
    """
    Associate the logical 'switch group' of a flag.
    - `-DDEF_=1` -> `-DDEF`
    - `-UDEF` -> `-DDEF`
    - `-Wno-error=unused` -> `-Wunused`
    - `-Wno-error` -> `-Werror`
    - `--sysroot=a/b/c` -> `--sysroot...`
    - `-O2` -> `-O...`
    """
    assert not is_multi_flag(flag)

    # e.g.
    # -D_DEF_=1 -> -D_DEF_
    # -U_DEF_ -> -D_DEF_
    m = re.search(r'^-[DU]([a-zA-Z_\\][a-zA-Z_\\0-9]*)=?', flag)
    if m:
        return '-D' + m.group(1)

    # e.g.
    # -Wno-error=unused-result -> -Wunused-result
    if any(flag.startswith(f) for f in WERROR_OPT_FLAGS):
        return '-W' + flag.split('=')[1]

    # e.g.
    # --sysroot=/a/b -> --sysroot...
    # but -fomit-frame-pointer, -O2 etc. remains
    m = re.search(r'^(--?[a-zA-Z][a-zA-Z0-9_-]*)=', flag)
    f = f'{m.group(1)}...' if m else flag

    # Handle special switches without assignment
    if f.startswith('-O'):
        return '-O...'
    if re.search(r'^-g[\d]?$', f):
        return '-g...'

    # -fno-omit-frame-pointer -> -fomit-frame-pointer
    return make_enabler(f)


def key_of_flag(f: str) -> str:
    """
    Get the represented logical option of a flag.
    """
    key = match_multi_flag(f)
    if key:
        return key
    return match_switch_flag(f)


def collect_flags_by_keys(flags: List[str]) -> Dict[str, List[str]]:
    """
    Collect flags by the logical option they represent.
    """

    res: Dict[str, List[str]] = {}
    for f in flags:
        key = key_of_flag(f)
        if key in res.keys():
            res[key].append(f)
        else:
            res[key] = [f]
    return res


def collect_extended_warning_sets(flags: List[str]) -> Dict[str, List[str]]:
    """
    Collect `-W` flags
    - -W(no-)x and -W(no-)error=x together,
    - along with the general (grouping) switches,
    - with consecutive duplicates removed
    """

    flags = [f for f in flags if f.startswith('-W')]

    general_flags: List[str] = []
    res: Dict[str, List[str]] = {}

    def add_to_all_registered(f: str):
        for v in res.values():
            v.append(f)

    for f in flags:
        key = make_enabler(f)
        f_is_general = bool(key in GENERAL_W_FLAGS)
        if key.startswith('-Werror='):
            key = key.replace('-Werror=', '-W')

        if f_is_general:
            general_flags.append(f)
            add_to_all_registered(f)
        elif key in res.keys():
            res[key].append(f)
        else:
            res[key] = general_flags + [f]

    def reduce(ls: List[str]) -> List[str]:
        return [ls[0]] + [e for i, e in enumerate(ls[1:]) if e != ls[i]]

    return {k: reduce(v) for k, v in res.items()}


def get_maybe_ineffective_flags_of_set(flags: List[str]) -> Tuple[List[str], Dict]:
    """
    Analyze flag sequence to identify potentially ineffective specific flags
    """

    flags_as_enabler = [make_enabler(f) for f in flags]
    is_enabler = [flags[i] == f for i, f in enumerate(flags_as_enabler)]
    is_specific = [f not in GENERAL_W_FLAGS for f in flags_as_enabler]
    is_error = [f.startswith('-Werror') for f in flags_as_enabler]

    cat = list(zip(is_enabler, is_specific, is_error, strict=True))

    CAT_WA = (True, False, False)       # -Wall
    CAT_WNA = (False, False, False)     # -Wno-all
    CAT_WX = (True, True, False)        # -Wunused
    CAT_WNX = (False, True, False)      # -Wno-unused
    CAT_WE = (True, False, True)        # -Werror
    CAT_WNE = (False, False, True)      # -Wno-error
    CAT_WEX = (True, True, True)        # -Werror=unused
    CAT_WNEX = (False, True, True)      # -Wno-error=unused

    res: List[str] = []
    for i, f in enumerate(flags):
        rem = cat[i+1:]

        def in_remaining(remaining, *args) -> bool:
            return any(flag in args for flag in remaining)

        if ((cat[i] == CAT_WX and CAT_WNA in rem)       # -Wunused -Wno-all
            or (cat[i] == CAT_WNX and CAT_WA in rem)    # -Wno-unused -Wall
            # -Werror=unused -Wno-unused|-Wno-all|-Wno-error
            or (cat[i] == CAT_WEX and in_remaining(rem, CAT_WNX, CAT_WNA, CAT_WNE))
                # -Wno-error=unused -Wno-unused|-Wno-all|-Werror
                or (cat[i] == CAT_WNEX and in_remaining(rem, CAT_WNX, CAT_WNA, CAT_WE))):
            res.append(f)

    def to_str(c: Tuple[bool, bool, bool]) -> Tuple[str, str, str]:
        return ('en' if c[0] else 'dis',
                'spec' if c[1] else 'gen',
                'err' if c[2] else 'warn')
    dbg = {"flag_categories": list(zip(flags, (to_str(c) for c in cat)))} if res else {}
    return res, dbg


def get_maybe_ineffective_flags(flags: List[str]) -> Tuple[List[str], Dict]:

    debug = {}
    res: List[str] = []
    w_sets = collect_extended_warning_sets(flags)
    for k, v in w_sets.items():
        r, dbg = get_maybe_ineffective_flags_of_set(v)
        res += r
        if r:
            debug.setdefault(k, {})
            debug[k]['collected'] = v
            debug[k].update(dbg)

    return dedup(res), debug


def missing_flag_text(flag: str) -> str:
    return f'Missing flag \'{flag}\''


def contradicting_flag_text(flag: str) -> str:
    return f'Contradicting options of \'{flag}\''


def ineffective_flag_text(flag: str) -> str:
    return f'Flag may have no effect: \'{flag}\''


def duplicate_flag_text(flag: str) -> str:
    return f'Duplicate(s) found of \'{flag}\''


def get_duplicates(flags: List[str]) -> int:
    return len(flags) - len(set(flags))


def has_contradiction(flags: List[str]) -> bool:
    return len(set(flags)) != 1


@dataclass
class ConsistencyResult:
    duplicates: List[str] = field(default_factory=list)
    contra_keys: List[str] = field(default_factory=list)
    maybe_ineffective_flags: List[str] = field(default_factory=list)
    debug: Dict[str, Any] = field(default_factory=dict)


def check_consistency_of_collected(flags_by_keys: Dict[str, List[str]], level: ConsistencyLevel) -> ConsistencyResult:
    """
    Consistency check of flags collected to logical groups.
    """

    if level == ConsistencyLevel.NONE:
        return ConsistencyResult()

    contra_keys: List[str] = []
    duplicates: List[str] = []

    debug: Dict[str, Dict[str], Any] = {}

    def add_debug(k: str, v: List[str]):
        debug.setdefault(k, {})
        debug[k].setdefault('collected', [])
        debug[k]['collected'] = v

    for k, v in flags_by_keys.items():
        dup = get_duplicates(v) if level == ConsistencyLevel.ALL else 0
        if not is_multi_flag(k) and has_contradiction(v):
            contra_keys.append(k)
            add_debug(k, v)
        elif dup > 0:
            duplicates.append(k)
            add_debug(k, v)

    return ConsistencyResult(duplicates=duplicates,
                             contra_keys=contra_keys,
                             debug=debug)


def check_consistency(flags: List[str],
                      level: ConsistencyLevel,
                      to_check: Optional[List[str]] = None) -> ConsistencyResult:
    """
    Consistency check of a flag list.

    Args:
        flags: List of flags
        level: Switch to define the check features.
        to_check: Filter results to flags, defaults to all

    Return:
        ConsistencyResult:
            Bundle of
            - the list of flags having duplicates
            - the list of flag groups containing contradiction
            - the list of potentially ineffective flags
    """
    flags_by_keys = collect_flags_by_keys(flags)
    res = check_consistency_of_collected(flags_by_keys, level)
    if level >= ConsistencyLevel.INEFFECTIVE:
        res.maybe_ineffective_flags, dbg = get_maybe_ineffective_flags(flags)
        res.debug.update(dbg)

    if to_check:
        return filter_consistency_for_flags(orig=res, to_check=to_check, flags_by_keys=flags_by_keys)
    return res


def filter_consistency_for_flags(orig: ConsistencyResult,
                                 to_check: List[str],
                                 flags_by_keys: Dict[str, List[str]]) -> ConsistencyResult:
    """
    Drop consistency check result for not expected flags.
    """
    to_check_wo_banned = [e for e in to_check if not e.startswith(FLAG_BANNED_PREFIX)]

    def to_keep(k: str) -> bool:
        checked = flags_by_keys.get(k, []) + [k]
        return any(e for e in to_check_wo_banned if check_flag(e, checked))

    def filt(flags: List[str]) -> List[str]:
        return [f for f in flags if to_keep(f)]

    return ConsistencyResult(duplicates=filt(orig.duplicates),
                             contra_keys=filt(orig.contra_keys),
                             maybe_ineffective_flags=filt(orig.maybe_ineffective_flags),
                             debug=orig.debug)   # yes, debug is not filtered...


def check_flag(expected: str, flag_set: List[str]) -> bool:
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
    if expected.startswith(FLAG_BANNED_PREFIX):
        return not check_flag(expected.removeprefix(FLAG_BANNED_PREFIX), flag_set)
    if expected.startswith(FLAG_REGEX_PREFIX):
        normalized_flag = expected.removeprefix(FLAG_REGEX_PREFIX).replace(PATH_REPLACEMENT, PATH_REPLACEMENT_IN_REGEX)
        return any(re.search(normalized_flag, a) for a in flag_set)
    if expected.startswith('-'):
        return expected in flag_set
    if f'-{expected}' in flag_set:
        return True
    if f'--{expected}' in flag_set:
        return True
    return False


def check_flags(entry: CdbEntry, expected_flags: List[str]) -> List[str]:
    """
    Check if a set of compile flags is present (or not) in a CdbEntry,
    additionally log errors to stderr.

    Returns:
        The set of flags not matching the expectations.

    TODO:
        - support MSVC arguments
    """

    res: Set[str] = set()
    for f in expected_flags:
        if not check_flag(f, entry.args):
            res.add(f)
    return list(res)


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
class Layer:
    name: str = ''
    compilers: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    drop_flags: List[str] = field(default_factory=list)


@dataclass
class Config:
    base_dirs: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    compile_units: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    flags_by_compiler: Dict[str, List[str]] = field(default_factory=dict)
    flags_by_library: Dict[str, List[str]] = field(default_factory=dict)
    flags_by_file: Dict[str, List[str]] = field(default_factory=dict)
    presets: Dict[str, List[str]] = field(default_factory=dict)
    layers: List[Layer] = field(default_factory=list)
    consistency: ConsistencyLevel = field(default=ConsistencyLevel.NONE)
    consistency_on_expected: bool = False
    verbose: bool = False
    very_verbose: bool = False
    summary: bool = False
    extra: Dict[str, Union[bool, str, List[str]]] = field(default_factory=dict)

    @staticmethod
    def from_dict(val: Dict, report_foreign_keys: bool = False) -> 'Config':
        return update_config(Config(), val, report_foreign_keys=report_foreign_keys)

    @staticmethod
    def keys():
        return [f.name for f in fields(Config) if f.name != 'extra']


def select_from_lists(presets: Dict[str, List[str]], predicate: Callable[[str], bool]) -> List[str]:
    """
    Select from preset lists by predicate.

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
    if not cfg.flags_by_compiler:
        return []
    logging.getLogger().debug('Checking for flag preset by compiler ...')
    return select_from_lists(cfg.flags_by_compiler, lambda x: match_path(ref=x, path=comp))


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
    if not cfg.flags_by_library:
        return []
    logging.getLogger().debug('Checking for flag preset by library ...')
    return select_from_lists(cfg.flags_by_library, lambda x: in_libraries(out_file, x))


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
    if not cfg.flags_by_file:
        return []
    logging.getLogger().debug('Checking for flag preset by file name ...')
    return select_from_lists(cfg.flags_by_file, lambda x: in_files(file, x))


def is_matching_layer(layer: Layer, entry: CdbEntry) -> bool:
    """
    Check layer match.
    A layer is considered matching if _all_ filter lists contain at least one match or empty.
    """
    compiler_match = any(match_path(ref=c, path=entry.compiler) for c in layer.compilers) if layer.compilers else True
    lib_match = any(in_libraries(entry, l) for l in layer.libraries) if layer.libraries else True
    file_match = any(in_files(entry, f) for f in layer.files) if layer.files else True
    return compiler_match and lib_match and file_match


def get_matching_layers(layers: List[Layer], entry: CdbEntry) -> List[Layer]:
    """
    Fetch matching layers from configuration.
    """
    return [l for l in layers if is_matching_layer(l, entry)]


def resolve_preset_refs(presets: Dict[str, List[str]], flags: List[str]) -> List[str]:
    if not flags:
        return []

    if flags[0].startswith(PRESET_REF_PREFIX):
        preset_name = flags[0].removeprefix(PRESET_REF_PREFIX)
        front = resolve_preset_refs(presets, presets[preset_name])
    else:
        front = [flags[0]]

    return front + resolve_preset_refs(presets, flags[1:])


def apply_flags_by_layers(cfg: Config, entry: CdbEntry, flags: List[str]) -> List[str]:
    """
    Fetch flags for the matching layers predefined in the configuration.

    Args:
        cfg: Config
        entry: CdbEntry
        flags: Collected flag set before applying layers

    Returns:
        List[str]: Flags aggregated from all matching layers
    """

    def resolve_refs(f: List[str]) -> List[str]:
        return resolve_preset_refs(cfg.presets, f)

    flags = resolve_refs(flags)
    if not cfg.layers:
        return flags

    logger = logging.getLogger()
    logger.debug('Checking for matching layers ...')
    matching = get_matching_layers(cfg.layers, entry)
    for i, m in enumerate(matching):
        name = m.name if m.name else f'#{i}'
        logging.getLogger().debug(f'  ... matching: {name}')

        flags = [f for f in flags if f not in resolve_refs(m.drop_flags)]
        flags.extend(resolve_refs(m.flags))
    return flags


def get_relevant_flags(cfg: Config, entry: CdbEntry) -> List[str]:
    """
    Fetch all relevant flags by the configuration.

    Args:
        cfg: Config
        entry: CdbEntry

    Returns:
        List[str]: Deduplicated list of relevant flags
    """
    to_check = cfg.flags \
        + get_flags_by_compiler(cfg, entry.compiler) \
        + get_flags_by_library(cfg, entry.out_file) \
        + get_flags_by_file(cfg, entry.file)
    to_check = apply_flags_by_layers(cfg, entry, to_check)
    return dedup(to_check)


@dataclass
class ResultsByEntry:
    missing: List[str] = field(default_factory=list)
    contra: List[str] = field(default_factory=list)
    duplicates: List[str] = field(default_factory=list)
    maybe_ineffective_flags: List[str] = field(default_factory=list)
    debug: Dict[str, Dict[str, Any]] = field(default_factory=dict)


def has_to_report_entries(cfg: Config) -> bool:
    return cfg.verbose or cfg.very_verbose or not cfg.summary


def report_entry(file: str, res: ResultsByEntry, cfg: Config):
    logger = logging.getLogger()

    missing_lines = [f'{file}: {missing_flag_text(f)}' for f in res.missing]
    cons_lines = [f'{file}: {contradicting_flag_text(f)}' for f in res.contra]
    cons_lines += [f'{file}: {ineffective_flag_text(f)}' for f in res.maybe_ineffective_flags]
    cons_lines += [f'{file}: {duplicate_flag_text(f)}' for f in res.duplicates]

    if cons_lines:
        logger.debug('')
        logger.warning('\n'.join(cons_lines))

    if missing_lines:
        logger.debug('')
        logger.warning('\n'.join(missing_lines))
    elif not cons_lines:
        logger.debug('\nAll expected flags OK')
    else:
        logger.debug('\nAll expected flags present but may be ineffective')

    if cfg.very_verbose and res.debug.get('consistency', {}):
        logger.debug('\nDebug data of consistency check result:')
        dbg = pprint.pformat(res.debug['consistency'], width=100, sort_dicts=False)
        logger.debug(dbg)


def check_entry(entry: CdbEntry, cfg: Config, dump: bool = False) -> ResultsByEntry:
    """
    Perform flag check on a CdbEntry by flags fetched from the configuration.

    Returns:
        The set of flags not matching the expectations.
    """

    logger = logging.getLogger()
    logger.debug(LOG_SEPARATOR)
    logger.debug(f'Entry {entry.file} ...')

    to_check = get_relevant_flags(cfg, entry)

    if dump:
        dump_entry(entry)
        return ResultsByEntry()

    logger.debug(f'Expecting {pprint.pformat(to_check) if to_check else "none"}')

    consistency = check_consistency(entry.orig_args,
                                    cfg.consistency,
                                    to_check=to_check if cfg.consistency_on_expected else None)

    debug = {}
    if consistency.debug:
        debug['consistency'] = consistency.debug

    res = ResultsByEntry(duplicates=consistency.duplicates,
                         contra=consistency.contra_keys,
                         maybe_ineffective_flags=consistency.maybe_ineffective_flags,
                         missing=check_flags(entry, to_check),
                         debug=debug)

    if has_to_report_entries(cfg):
        report_entry(file=entry.file, res=res, cfg=cfg)

    return res


CheckResult = Dict[str, Set[str]]


def add_to_result(res: CheckResult, entry: CdbEntry, by_entry: ResultsByEntry):
    """
    Add the missing flag set of a CdbEntry to the aggregated result.
    """
    def add_one(error: str):
        l = res.get(error, set())
        l.add(entry.file)
        res[error] = l

    for f in by_entry.missing:
        add_one(missing_flag_text(f))
    for f in by_entry.contra:
        add_one(contradicting_flag_text(f))
    for f in by_entry.maybe_ineffective_flags:
        add_one(ineffective_flag_text(f))
    for f in by_entry.duplicates:
        add_one(duplicate_flag_text(f))


def summary_report(result: CheckResult):

    logger = logging.getLogger()

    def file_list(files: Set[str]) -> str:
        assert files
        INDENT = ' ' * 2
        LIMIT = 5
        files_as_string = '\n'.join([INDENT + f for f in list(files)[0:LIMIT]])
        if len(files) > LIMIT:
            files_as_string += f'\n{INDENT}... and {(len(files) - LIMIT)} more'
        return files_as_string

    for error, entries in result.items():
        logger.warning(f'{error}: {len(entries)} issue(s) in')
        logger.warning(file_list(entries))


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
    logger.debug(f'Checking {len(cdb)}{qualifier} entries(s) ...')

    if not cdb:
        logger.warning('No compilation to check.')
        logger.warning('Please verify the effective configuration using the -v/--verbose argument.')
        return False

    res: CheckResult = {}

    for e in cdb:
        res_by_entry = check_entry(e, cfg, dump=dump)
        add_to_result(res, e, res_by_entry)

    if cfg.summary:
        logger.debug(LOG_SEPARATOR)
        logger.debug('Creating summary...')
        summary_report(res)

    return not res


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
    foreign_keys = [k for k in foreign_keys if k != '$schema']

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
        if k == 'layers':
            to_add = [Layer(**d) for d in data_to_add[k]]
        else:
            to_add = data_to_add[k]
        setattr(updated, k, add(getattr(updated, k), to_add))

    for k in foreign_keys:
        updated.extra[k] = data_to_add[k]

    if report_foreign_keys and foreign_keys:
        keys_logged = ', '. join(foreign_keys)
        logging.getLogger().warning('Foreign keys in config file:')
        logging.getLogger().warning(f'  {keys_logged}')

    return updated


def load_yaml_config(f) -> Dict:

    # It's ugly but I decided to use a local import here as
    # didn't want to introduce dependency to a non-default package
    # unless it's used.
    import yaml

    cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict):
        raise ValueError('Invalid config file')
    return cfg


def load_config(file: str) -> Dict:
    """
    Load config file to a dictionary.
    """
    with open(file, encoding='utf-8') as f:

        if file.endswith('.yaml') or file.endswith('.yml'):
            return load_yaml_config(f)

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
    parser.add_argument('-c', '--config', help='Config file (JSON/YAML)')

    parser.add_argument('-f', '--flags', nargs='+', help='Flags to check, passed without \'-\' prefix')
    parser.add_argument('-cc', '--consistency',
                        type=lambda x: ConsistencyLevel(int(x)),
                        choices=[e.value for e in ConsistencyLevel],
                        default=ConsistencyLevel.CONTRADICTING,
                        help=f'Consistency check level [default: {ConsistencyLevel.CONTRADICTING.value}]')

    parser.add_argument('-ce', '--consistency-on-expected', action='store_true',
                        help='Report consistency check warnings only for the expected flags')

    in_opts = parser.add_argument_group('Input configuration')

    in_opts.add_argument('-b', '--base-dirs', nargs='+',
                         help='Path prefixes to remove, either absolute or relative to $PWD')
    in_opts.add_argument('-u', '--compile-units', nargs='+', help='Compile units to check, default: all')
    in_opts.add_argument('-l',
                         '--libraries',
                         nargs='+',
                         help='Logical \'libraries\' to check, default: all')

    out_opts = parser.add_argument_group('Output configuration')

    out_mx_opts = out_opts.add_mutually_exclusive_group()
    out_mx_opts.add_argument('-s', '--summary', action='store_true', help='Summarize results')
    out_mx_opts.add_argument('-d', '--dump', action='store_true', help='Dump entries to check')
    out_mx_log_opts = out_opts.add_mutually_exclusive_group()
    out_mx_log_opts.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    out_mx_log_opts.add_argument('-vv', '--very-verbose', action='store_true', help='Very verbose logging')

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

    configure_logging(args.verbose or args.very_verbose)
    logger = logging.getLogger()

    if args.verbose or args.very_verbose:
        logger.debug('cdb-check - running in verbose mode')
        logger.debug('Configuration:')
        logger.debug(pprint.pformat(cfg, width=100, sort_dicts=False))

    if process(args.input,
               cfg=cfg,
               dump=args.dump):
        logger.info('OK')
    else:
        exit(1)


if __name__ == "__main__":
    main()
