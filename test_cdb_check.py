#!/usr/bin/env python3

from copy import deepcopy
from cdb_check import *


def test_path_wildcards_to_regex():

    assert path_wildcards_to_regex('') == ''
    assert path_wildcards_to_regex('abc/cde') == 'abc/cde'
    assert path_wildcards_to_regex('abc+/.cde/(a)') == 'abc\\+/\\.cde/\\(a\\)'

    assert path_wildcards_to_regex('abc/*') == 'abc/[^/]+'
    assert path_wildcards_to_regex('abc/*/b.c') == 'abc/[^/]+/b\\.c'
    assert path_wildcards_to_regex('abc/*.cpp') == 'abc/[^/]*\\.cpp'
    assert path_wildcards_to_regex('abc/*/b.*') == 'abc/[^/]+/b\\.[^/]*'

    assert path_wildcards_to_regex('abc/**') == 'abc(/.+)?'
    assert path_wildcards_to_regex('abc/**/c') == 'abc(/.+)?/c'
    assert path_wildcards_to_regex('abc/**/b/**') == 'abc(/.+)?/b(/.+)?'
    assert path_wildcards_to_regex('**/a') == '(.*/)?a'
    assert path_wildcards_to_regex('**') == '.+'

    assert path_wildcards_to_regex('ab?/a') == 'ab[^/]/a'

    assert path_wildcards_to_regex('abc/[cd]e') == 'abc/[cd]e'
    assert path_wildcards_to_regex('abc/[?]e/f[!]') == 'abc/[\\?]e/f[!]'

    assert path_wildcards_to_regex('abc/[!cd]e') == 'abc/[^cd]e'
    assert path_wildcards_to_regex('abc/[!?]e/f[!!]') == 'abc/[^\\?]e/f[^!]'


def test_match_path_basic():

    assert not match_path('', 'abc')
    assert match_path('abc/cde', 'abc/cde')
    assert not match_path('abc/cde', 'abc/cdef')

    assert match_path('cde', 'abs/cde')
    assert not match_path('de', 'abs/cde')
    assert not match_path('/cde', 'abs/cde')

    assert match_path('abc+/.cde/(a)', 'abc+/.cde/(a)')


def test_match_path_prefixed():

    assert match_path('abc/cde', '[...]abc/cde')
    assert match_path('abc/cde', '[...]/abc/cde')


def test_match_path_wildcard_segment():

    r = 'abc/*'

    assert match_path(r, 'abc/a.c')
    assert match_path(r, 'abc/b')
    assert not match_path(r, 'abc/')
    assert not match_path(r, 'abc/b/b.c')

    r = 'abc/*/b.c'

    assert not match_path(r, 'abc/a.c')
    assert not match_path(r, 'abc/b.c')
    assert not match_path(r, 'abc/')
    assert match_path(r, 'abc/b/b.c')
    assert match_path(r, 'abc/bcd/b.c')
    assert not match_path(r, 'abc/bcd/def/b.c')


def test_match_path_wildcard_part():

    r = 'abc/*.cpp'

    assert match_path(r, 'abc/.cpp')
    assert match_path(r, 'abc/a.cpp')
    assert match_path(r, 'abc/a.b.cpp')
    assert not match_path(r, 'abc/a.c')
    assert not match_path(r, 'abc/b/a.cpp')
    assert not match_path(r, 'abc/a.cpp/a.cpp')


def test_match_path_recursive_wildcard():

    r = 'abc/**'

    assert match_path(r, 'abc/b/c.py')
    assert match_path(r, 'abc/d.py')
    assert match_path(r, 'abc/b/c/e.py')

    r = 'abc/**/c'

    assert match_path(r, 'abc/c')
    assert match_path(r, 'abc/b/c')
    assert match_path(r, 'abc/b/c/c')
    assert not match_path(r, 'abc/b/c/d')

    r = 'abc/**/b/**'

    assert match_path(r, 'abc/b')
    assert match_path(r, 'abc/b/a')
    assert match_path(r, 'abc/x/b')
    assert match_path(r, 'abc/x/b/c/d')

    r = '**/b/**/*.cpp'

    assert not match_path(r, 'abc/b')
    assert match_path(r, 'abc/b/e.cpp')
    assert match_path(r, 'abc/b/c/d/e.cpp')
    assert match_path(r, 'b/c/d/e.cpp')
    assert match_path(r, 'b/e.cpp')
    assert match_path(r, '/b/e.cpp')


def test_match_path_any_char():

    r = 'ab?/a'

    assert match_path(r, 'abc/a')
    assert match_path(r, 'abd/a')
    assert not match_path(r, 'abde/a')
    assert not match_path(r, 'ab/a')


def test_match_path_char_set():

    r = 'abc/[cd]e'

    assert match_path(r, 'abc/de')
    assert not match_path(r, 'abc/ee')

    r = 'abc/[?]e/f[!]'

    assert match_path(r, 'abc/?e/f!')


def test_match_path_negative_char_set():

    r = 'abc/[!cd]e'

    assert not match_path(r, 'abc/de')
    assert match_path(r, 'abc/ee')

    r = 'abc/[!?]e/f[!!]'

    assert not match_path(r, 'abc/?e/fe')
    assert not match_path(r, 'abc/ee/f!')
    assert match_path(r, 'abc/ee/fe')


def test_dedup():
    assert dedup([1, 1, 2, 1, 2, 3]) == [1, 2, 3]


def test_to_entry():

    RAW_ENTRY = {
        'directory': '/path/to/build',
        'command': '/usr/bin/gcc-8 -DOPT_1=1 -DOPT_2 -DOPT_3="quoted text" '
                   '-DOPT_4=\\"quoted text\\" -I/path/to_inc -o out/file.c.o -c src/file.c',
        'file': '/path/to/src/src.c'
    }

    e = to_entry(RAW_ENTRY)

    assert e.file == RAW_ENTRY['file']
    assert e.directory == '/path/to/build'
    assert e.compiler == RAW_ENTRY['command'].split()[0]
    assert e.args[0] == '-DOPT_1=1'
    assert e.args[2] == '-DOPT_3=quoted text'
    assert e.args[3] == '-DOPT_4="quoted'
    assert e.args[4] == 'text"'
    assert e.args[-1] == 'src/file.c'
    assert e.out_file == 'out/file.c.o'

    RAW_ENTRY_ARG = {
        'directory': '/path/to/build',
        'arguments': ['/usr/bin/gcc-8', '-DOPT_1=1', '-DOPT_2', '-DOPT_3=quoted text',
                      '-DOPT_4="quoted text"', '-I/path/to_inc', '-o', 'out/file.c.o', '-c', 'src/file.c'],
        'file': '/path/to/src/src.c'
    }

    e = to_entry(RAW_ENTRY_ARG)
    assert e.file == RAW_ENTRY_ARG['file']
    assert e.compiler == RAW_ENTRY_ARG['arguments'][0]
    assert e.args[2] == '-DOPT_3=quoted text'
    assert e.args[3] == '-DOPT_4="quoted text"'
    assert e.args[-1] == 'src/file.c'
    assert e.out_file == 'out/file.c.o'


def test_replace_path_prefix():

    WORK_DIR = '/work'
    BASE_DIRS = ['/abs/path', '/work/path']

    assert replace_path_prefix(BASE_DIRS[0], WORK_DIR, BASE_DIRS) == '[...]'
    assert replace_path_prefix(BASE_DIRS[1], WORK_DIR, BASE_DIRS) == '[...]'

    assert replace_path_prefix('/abs/path/to/file', WORK_DIR, BASE_DIRS) == '[...]/to/file'
    assert replace_path_prefix('path/to/file', WORK_DIR, BASE_DIRS) == '[...]/to/file'
    assert replace_path_prefix('other/path/to/file', WORK_DIR, BASE_DIRS) == '/work/other/path/to/file'


def test_join_opt_pairs():

    assert join_opt_pairs([]) == []
    assert join_opt_pairs(['a']) == ['a']
    assert join_opt_pairs(['-a']) == ['-a']

    assert join_opt_pairs(['-a', '-b', '-c', '-d']) == ['-a', '-b', '-c', '-d']
    assert join_opt_pairs(['a', '-b', '-c', '-d']) == ['a', '-b', '-c', '-d']

    assert join_opt_pairs(['-a', '-b', '-c', 'd']) == ['-a', '-b', '-c d']
    assert join_opt_pairs(['-a', '-b', 'c', '-d']) == ['-a', '-b c', '-d']
    assert join_opt_pairs(['-a', 'b', 'c', 'd']) == ['-a b c d']


def test_normalize_base_dirs():

    ABS = '/abs/path'
    REL = 'rel/path'
    cwd = str(Path.cwd())
    bd = normalize_base_dirs([ABS, REL])
    assert bd == [ABS, f'{cwd}/{REL}']


TEST_FLAGS = [
    '-A1',
    '-c',
    'xxx',
    '-A2',
    '-o',
    'yyy',
    '-Irelative/include',
    '-I/path/to/src/include',
    '-isystem',
    '/path/to/src/include',
    '--sysroot=/path/to/toolchain/include',
]

TEST_ENTRY = CdbEntry(file='/path/to/src/file.c',
                      directory='/path/to/build',
                      compiler='/path/to/compiler/gcc',
                      args=TEST_FLAGS,
                      out_file='/path/to/build/CMakeFiles/lib.dir/src/file.c.o')


def test_normalize_join_pairs_args():

    e = normalize(TEST_ENTRY)
    assert '-isystem /path/to/src/include' in e.args


def test_normalize_drop_args():

    e = normalize(TEST_ENTRY)

    EXPECTED_DROPPED = 4
    EXPECTED_JOINT = 1

    assert e.file == TEST_ENTRY.file
    assert e.compiler == TEST_ENTRY.compiler
    assert len(e.args) == len(TEST_ENTRY.args) - EXPECTED_DROPPED - EXPECTED_JOINT
    assert '-c' not in e.args
    assert 'yyy' not in e.args

    ENTRY_MISSING_OBJ = copy.copy(TEST_ENTRY)
    ENTRY_MISSING_OBJ.args = [a for a in TEST_ENTRY.args if a not in ['-o', 'yyy']]

    e2 = normalize(ENTRY_MISSING_OBJ)
    assert len(e2.args) == len(ENTRY_MISSING_OBJ.args) - 2 - EXPECTED_JOINT
    assert '-c' not in e2.args
    assert 'xxx' not in e2.args


def test_normalize_trim_path():

    e = normalize(TEST_ENTRY, ['/path/to'])

    assert e.file.startswith('[...]/src/')
    assert e.directory == '[...]/build'
    assert e.compiler.startswith('[...]/compiler')
    assert e.out_file.startswith('[...]/build/')

    assert e.args[-4] == '-Irelative/include'
    assert e.args[-3] == '-I[...]/src/include'
    assert e.args[-2] == '-isystem [...]/src/include'

    assert e.args[-1] == '--sysroot=[...]/toolchain/include'


def test_make_enabler():

    assert make_enabler('-I/p') == '-I/p'
    assert make_enabler('-Werror') == '-Werror'
    assert make_enabler('-Gno') == '-Gno'
    assert make_enabler('-Wno-error') == '-Werror'
    assert make_enabler('-fno-err') == '-ferr'


def test_werror_enabled():

    assert not werror_enabled([])
    assert not werror_enabled(['a', 'b'])

    assert werror_enabled(['a', '-Werror', 'b'])
    assert not werror_enabled(['a', '-Werror', 'b', '-Wno-error'])
    assert werror_enabled(['-Werror', '-Wno-error', '-Werror'])


def test_match_switch_flag():

    # trivial
    assert match_switch_flag('-Wall') == '-Wall'
    assert match_switch_flag('-Wunused') == '-Wunused'
    assert match_switch_flag('-Werror') == '-Werror'

    # disablers
    assert match_switch_flag('-fno-omit-frame-pointer') == '-fomit-frame-pointer'
    assert match_switch_flag('-Wno-unused') == '-Wunused'

    # selective Werror
    assert match_switch_flag('-Werror=unused') == '-Wunused'
    assert match_switch_flag('-Wno-error=unused') == '-Wunused'

    # preprocessor
    assert match_switch_flag('-DDEF') == '-DDEF'
    assert match_switch_flag('-D_DEF=34') == '-D_DEF'
    assert match_switch_flag('-U_DEF') == '-D_DEF'

    assert match_switch_flag('-DA') == '-DA'
    assert match_switch_flag('-D\\u0013') == '-D\\u0013'

    assert match_switch_flag('-U2_DEF') != '-D2_DEF'

    # specials
    assert match_switch_flag('-O2') == '-O...'
    assert match_switch_flag('-Os') == '-O...'
    assert match_switch_flag('-g') == '-g...'
    assert match_switch_flag('-g2') == '-g...'


def test_collect_flags_by_keys_trivial():

    c = collect_flags_by_keys(['-a', '-b', '-c'])
    assert {'-a', '-b', '-c'} == set(c.keys())
    for k, v in c.items():
        assert v == [k]


def test_collect_flags_by_keys_multi():

    FLAGS = ['-Ia/b', '-I=b/c', '-I c/d', '-isystem a/b', '-isystem b/c']

    c = collect_flags_by_keys(FLAGS)
    assert set(c.keys()) == set(FLAGS)
    for k, v in c.items():
        assert v == [k]


def test_collect_flags_by_keys_with_value():

    c = collect_flags_by_keys(['-O1', '-O2', '-Ww=12', '-g', '--Ww=13', '-g3'])
    assert {'-O...', '-Ww...', '--Ww...', '-g...'} == set(c.keys())
    assert c['-O...'] == ['-O1', '-O2']
    assert c['-Ww...'] == ['-Ww=12']
    assert c['-g...'] == ['-g', '-g3']


def test_collect_flags_by_keys_disablers():

    c = collect_flags_by_keys(['-fa', '-fno-a', '-fa'])
    assert {'-fa'} == set(c.keys())
    assert c['-fa'] == ['-fa', '-fno-a', '-fa']


def test_collect_flags_by_keys_werror():

    c = collect_flags_by_keys(['-Wunused', '-Wno-unused', '-Werror=unused', '-Wno-error=unused'])
    assert {'-Wunused'} == set(c.keys())
    assert len(c['-Wunused']) == 4


def test_get_duplicates():

    assert get_duplicates(['-Wall']) == 0
    assert get_duplicates(['-Wall', '-Wall']) == 1
    assert get_duplicates(['-Wall', '-Wno-all']) == 0
    assert get_duplicates(['-Wall', '-Wno-all'] * 2) == 2


def test_key_of_flag():

    assert key_of_flag('--sysroot=/p/t/sr') == '--sysroot...'
    assert key_of_flag('-O1') == '-O...'
    assert key_of_flag('-fno-omit-frame-pointer') == '-fomit-frame-pointer'
    assert key_of_flag('-Wall') == '-Wall'
    assert key_of_flag('-Wno-error=unused-result') == '-Wunused-result'


def test_collect_flags_by_keys():

    FLAGS = [
        '-Werror',
        '-fomit-frame-pointer',
        '-Wno-error=unused-result',
        '-I/p/t/i',
        '-I/p/t/i2',
        '-fno-omit-frame-pointer',
        '-fomit-frame-pointer',
        '-I/p/t/i',
        '-Werror',
        '-O1',
        '-Os',
        '-g',
        '-g1',
        '--sysroot=/p/t/sr',
        '--sysroot=/p/t/sr',
        '-DA',
        '-UA',
        '-DA=4',
    ]

    EXPECTED = {
        '-Werror': ['-Werror', '-Werror'],
        '-fomit-frame-pointer': ['-fomit-frame-pointer', '-fno-omit-frame-pointer', '-fomit-frame-pointer'],
        '-Wunused-result': ['-Wno-error=unused-result'],
        '-I/p/t/i': ['-I/p/t/i', '-I/p/t/i'],
        '-I/p/t/i2': ['-I/p/t/i2'],
        '-O...': ['-O1', '-Os'],
        '-g...': ['-g', '-g1'],
        '--sysroot...': ['--sysroot=/p/t/sr', '--sysroot=/p/t/sr'],
        '-DA': ['-DA', '-UA', '-DA=4']
    }

    assert collect_flags_by_keys(FLAGS) == EXPECTED


def test_collect_extended_warning_sets():

    FLAGS = [
        '-fomit-frame-pointer',
        '-Werror',
        '-Wno-error=unused',
        '-Os',
        '-Wall',
        '-Wno-array',
        '-Os',
        '-Wall',
        '-Wunused',
        '-Wno-unused',
        '-Wno-extra',
    ]

    res = collect_extended_warning_sets(FLAGS)

    assert res['-Warray'] == ['-Werror', '-Wall', '-Wno-array', '-Wall', '-Wno-extra']
    assert res['-Wunused'] == ['-Werror', '-Wno-error=unused', '-Wall', '-Wunused', '-Wno-unused', '-Wno-extra']

    assert '-Werror=unused' not in res
    assert '-Werror' not in res
    assert '-Wall' not in res
    assert '-Wextra' not in res
    assert '-Wno-extra' not in res
    assert '-Os' not in res


def test_get_maybe_ineffective_flags_of_set():

    assert get_maybe_ineffective_flags_of_set(['-Wunused', '-Wno-all'])[0] == ['-Wunused']
    assert get_maybe_ineffective_flags_of_set(['-Wall', '-Wunused', '-Wno-all', '-Wall'])[0] == ['-Wunused']

    assert get_maybe_ineffective_flags_of_set(['-Wall', '-Wno-unused', '-Werror', '-Wall'])[0] == ['-Wno-unused']

    assert get_maybe_ineffective_flags_of_set(['-Wall', '-Werror=unused', '-Wno-unused'])[0] == ['-Werror=unused']
    assert get_maybe_ineffective_flags_of_set(['-Wall', '-Werror=unused', '-Wno-all'])[0] == ['-Werror=unused']
    assert get_maybe_ineffective_flags_of_set(['-Wall', '-Werror=unused', '-Wno-error'])[0] == ['-Werror=unused']
    assert not get_maybe_ineffective_flags_of_set(['-Wall', '-Werror=unused', '-Werror'])[0]

    assert get_maybe_ineffective_flags_of_set(
        ['-Wall', '-Werror', '-Wno-error=unused', '-Wno-unused'])[0] == ['-Wno-error=unused']
    assert get_maybe_ineffective_flags_of_set(
        ['-Wall', '-Werror', '-Wno-error=unused', '-Wno-all'])[0] == ['-Wno-error=unused']
    assert get_maybe_ineffective_flags_of_set(
        ['-Wall', '-Werror', '-Wno-error=unused', '-Werror'])[0] == ['-Wno-error=unused']
    assert not get_maybe_ineffective_flags_of_set(['-Wall', '-Werror', '-Wno-error=unused', '-Wno-error'])[0]


def test_get_maybe_ineffective_flags():

    FLAGS = [
        '-fomit-frame-pointer',
        '-Werror',
        '-Wno-error=unused',    # ineffective due to -Wunused
        '-Os',
        '-Wall',
        '-Wno-array',           # ineffective due to -Wall
        '-Os',
        '-Wall',
        '-Wunused',             # ineffective due to -Wno-extra
        '-Wno-unused',
        '-Wno-extra',
    ]

    res, _ = get_maybe_ineffective_flags(FLAGS)

    assert '-Wno-error=unused' in res
    assert '-Wno-array' in res
    assert '-Wunused' in res
    assert len(res) == 3


def test_has_contradiction():

    assert not has_contradiction(['-Wa'])
    assert not has_contradiction(['-Wa', '-Wa'])

    assert has_contradiction(['-Wa', '-Wno-a'])
    assert has_contradiction(['-Wa', '-Wno-a', '-Wa'])
    assert has_contradiction(['-O1', '-Os'])


def test_check_consistency_of_collected():

    COLLECTED = {
        '-Werror': ['-Werror', '-Werror'],
        '-fomit-frame-pointer': ['-fomit-frame-pointer', '-fno-omit-frame-pointer', '-fomit-frame-pointer'],
        '-Wunused-result': ['-Wno-error=unused-result'],
        '-I/p/t/i': ['-I/p/t/i', '-I/p/t/i'],
        '-I/p/t/i2': ['-I/p/t/i2'],
        '-O...': ['-O1', '-Os'],
        '-g...': ['-g', '-g1'],
        '--sysroot...': ['--sysroot=/p/t/sr', '--sysroot=/p/t/sr']
    }

    CONTRA_KEYS = ['-fomit-frame-pointer', '-O...', '-g...']

    res = check_consistency_of_collected(COLLECTED, ConsistencyLevel.NONE)
    assert not res.contra_keys
    assert not res.duplicates
    assert not res.maybe_ineffective_flags

    res = check_consistency_of_collected(COLLECTED, ConsistencyLevel.CONTRADICTING)
    assert res.contra_keys == CONTRA_KEYS
    assert not res.duplicates
    assert not res.maybe_ineffective_flags

    res = check_consistency_of_collected(COLLECTED, ConsistencyLevel.ALL)
    assert res.contra_keys == CONTRA_KEYS
    assert res.duplicates == ['-Werror', '-I/p/t/i', '--sysroot...']
    assert not res.maybe_ineffective_flags


def test_filter_consistency_for_flags():

    BY_KEYS = collect_flags_by_keys(['-O1', '-O2', '-O2', '-g', '-g', '-Werror', '-Wall',
                                    '-Wno-all', '-fsanitize', '-Wunused', '-Warray'])

    CONS = ConsistencyResult(duplicates=['-g...', '-O...'],
                             contra_keys=['-Werror', '-Wall', '-fsanitize'],
                             maybe_ineffective_flags=['-Wunused', '-Warray'])

    res = filter_consistency_for_flags(CONS,
                                       to_check=['-O2', '-Wno-all', '-Warray', '!-Werror'],
                                       flags_by_keys=BY_KEYS)

    assert res.duplicates == ['-O...']
    assert res.contra_keys == ['-Wall']
    assert res.maybe_ineffective_flags == ['-Warray']


def test_check_consistency():

    F1 = [
        '-fomit-frame-pointer',
        '-fno-omit-frame-pointer',
        '-DDEF=2',
        '-DDEF=3'
    ]

    res = check_consistency(F1, ConsistencyLevel.ALL)
    assert res.contra_keys == ['-fomit-frame-pointer', '-DDEF']

    F2 = [
        '-Werror',
        '-Wno-error',
        '-Wno-error=unused-result',
        '-Wunused-result',
    ]

    res = check_consistency(F2, ConsistencyLevel.ALL)
    assert res.contra_keys == ['-Werror', '-Wunused-result']

    F3 = [
        '--sysroot=a/b',
        '--sysroot=b/c',
        '-g1',
        '-g',
    ]

    res = check_consistency(F3, ConsistencyLevel.ALL)
    assert res.contra_keys == ['--sysroot...', '-g...']

    F4 = [
        '-Werror=unused-result',
        '-Wno-all',
        '-g1',
        '-g1',
    ]

    res = check_consistency(F4, ConsistencyLevel.ALL)
    assert not res.contra_keys
    assert res.duplicates == ['-g...']
    assert res.maybe_ineffective_flags == ['-Werror=unused-result']


def test_check_flag_no_prefix():

    assert not check_flag('', TEST_FLAGS)
    assert not check_flag('A5', TEST_FLAGS)

    assert check_flag('A2', TEST_FLAGS)


def test_check_flag_with_prefix():

    assert check_flag('-A1', TEST_FLAGS)
    assert check_flag('--sysroot=/path/to/toolchain/include', TEST_FLAGS)

    assert not check_flag('--A1', TEST_FLAGS)
    assert not check_flag('-sysroot=/path/to/toolchain/include', TEST_FLAGS)


def test_check_flag_regex():

    assert check_flag('#A', TEST_FLAGS)
    assert check_flag('#A[0-9]', TEST_FLAGS)
    assert not check_flag('#A[a-z]', TEST_FLAGS)
    assert check_flag('#^-A[\\d]$', TEST_FLAGS)

    assert check_flag('#^--sys', TEST_FLAGS)
    assert not check_flag('#^B', TEST_FLAGS)


def test_check_flag_path_replacement():

    FLAGS_WITH_PATH_REPLACEMENT = [
        "-I[...]/include",
        "--sysroot=[...]/comp-1.2.3"
    ]

    assert check_flag('I[...]/include', FLAGS_WITH_PATH_REPLACEMENT)
    assert check_flag('#^--sysroot=[...]/comp-.*', FLAGS_WITH_PATH_REPLACEMENT)


def test_check_flag_banned():

    assert not check_flag('!A2', TEST_FLAGS)
    assert check_flag('!A5', TEST_FLAGS)

    assert check_flag('!--A2', TEST_FLAGS)
    assert not check_flag('!-A2', TEST_FLAGS)

    assert not check_flag('!#A[0-9]', TEST_FLAGS)
    assert check_flag('!#A[a-z]', TEST_FLAGS)


def test_check_flags():

    assert check_flags(TEST_ENTRY, []) == []
    assert check_flags(TEST_ENTRY, ['A2']) == []
    assert check_flags(TEST_ENTRY, ['A1', '-A2']) == []

    assert check_flags(TEST_ENTRY, ['A1', 'A7']) == ['A7']

    assert check_flags(TEST_ENTRY, ['sysroot=/path/to/toolchain/include']) == []
    assert check_flags(TEST_ENTRY, ['!#A[a-z]', '#A[0-9]']) == []

    assert check_flags(TEST_ENTRY, ['#^-A[\\d]$']) == []


def test_in_files_lexical():

    FILE = '/path/to/src/file.c'
    FILE_2 = '/path/to/src/file2.c'

    assert not in_files(FILE, [])
    assert not in_files(FILE, 'src/file4.c')

    assert in_files(FILE, FILE)
    assert not in_files(FILE_2, FILE)

    assert in_files(FILE, 'file.c')
    assert not in_files(FILE, 'src/file.c')
    assert in_files(TEST_ENTRY, 'file.c')

    assert not in_files(FILE_2, 'file.c')
    assert in_files(FILE_2, ['file.c', 'file2.c'])


def test_in_files_matched():

    FILE = '/path/to/src/file.c'

    assert not in_files(FILE, '*.c')
    assert not in_files(FILE, '*/file.c')
    assert in_files(FILE, '**/*.c')
    assert in_files(FILE, ['**/*.cpp', '**/*.c'])

    assert not in_files(FILE, 'src/*')
    assert in_files(FILE, '**/src/*')


def test_in_files_replaced():

    FILE = '[...]/src/file.c'

    assert in_files(FILE, 'src/file.c')
    assert in_files(FILE, '*/file.c')


def test_in_libraries():

    assert not in_libraries(TEST_ENTRY, [])
    assert not in_libraries(TEST_ENTRY, 'some-lib-name')

    assert in_libraries(TEST_ENTRY, 'lib')
    assert in_libraries(TEST_ENTRY.out_file, 'lib')

    assert in_libraries(TEST_ENTRY, ['lib'])
    assert in_libraries(TEST_ENTRY, ['src'])
    assert in_libraries(TEST_ENTRY, ['lib', 'some-other-lib'])

    assert in_libraries(TEST_ENTRY, ['li?'])
    assert in_libraries(TEST_ENTRY, ['*ib'])


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
                     '**/g*-11': ['D11', 'E11'],
                 })

    assert not get_flags_by_compiler(CFG, '')
    assert not get_flags_by_compiler(CFG, 'gcc-4')

    f = get_flags_by_compiler(CFG, 'gcc-5')
    check(CFG.flags_by_compiler['gcc-5'], f)

    f = get_flags_by_compiler(CFG, 'g++-8')
    check(CFG.flags_by_compiler['g*-8'], f)

    f = get_flags_by_compiler(CFG, '/usr/bin/gcc-11')
    check(CFG.flags_by_compiler['**/g*-11'], f)

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
                        compiler='/path/to/compiler/bin/gcc',
                        args=['-A1', '-A2', '-I/path/to/src/include'],
                        out_file='/path/to/build/CMakeFiles/lib.dir/src/file2.c.o')

TEST_ENTRY_3 = CdbEntry(file='/path/to/src/file3.c',
                        directory='/path/to/build',
                        compiler='/path/to/compiler/gcc',
                        args=['-A1', '-A3', '-A4', '-I/path/to/src/include'],
                        out_file='/path/to/build/CMakeFiles/lib2.dir/src/file3.c.o')

FILE_LAYER = Layer(name='',
                   files=['**/*2.c', '**/*2.cpp'],
                   flags=['A2'])

LIBRARY_LAYER = Layer(name='',
                      libraries=['lib', 'another_lib'],
                      flags=['A2', 'A3'])

QCC_COMPILER_LAYER = Layer(name='',
                           compilers=['**/*qcc'],
                           flags=['A3', 'A4'])


def test_is_matching_layer():

    assert is_matching_layer(Layer(), TEST_ENTRY_2)

    assert is_matching_layer(FILE_LAYER, TEST_ENTRY_2)
    assert not is_matching_layer(FILE_LAYER, TEST_ENTRY_3)

    assert is_matching_layer(LIBRARY_LAYER, TEST_ENTRY_2)
    assert not is_matching_layer(LIBRARY_LAYER, TEST_ENTRY_3)

    COMPILER_LAYER = Layer(name='',
                           compilers=['**/*gcc'])

    assert is_matching_layer(COMPILER_LAYER, TEST_ENTRY_2)

    COMPLEX_LAYER = Layer(name='',
                          compilers=['**/*gcc'],
                          libraries=['lib2']
                          )

    assert not is_matching_layer(COMPLEX_LAYER, TEST_ENTRY_2)
    assert is_matching_layer(COMPLEX_LAYER, TEST_ENTRY_3)


def test_get_matching_layers():

    ALL_LAYERS = [LIBRARY_LAYER, QCC_COMPILER_LAYER, FILE_LAYER]
    assert get_matching_layers(ALL_LAYERS, TEST_ENTRY_2) == [LIBRARY_LAYER, FILE_LAYER]


def test_resolve_preset_refs():

    PRESETS = {
        'p1': ['A1', 'A0'],
        'p2': ['A2'],
        'p_ref': ['A1', '$p2', 'A3']
    }

    assert resolve_preset_refs({}, []) == []
    assert resolve_preset_refs(PRESETS, []) == []

    assert resolve_preset_refs(PRESETS, ['A1', 'A2']) == ['A1', 'A2']
    assert resolve_preset_refs(PRESETS, ['A1', '$p1']) == ['A1', 'A1', 'A0']
    assert resolve_preset_refs(PRESETS, ['$p_ref', 'A4']) == ['A1', 'A2', 'A3', 'A4']


def test_apply_flags_by_layers_no_layers():

    PRESETS = {
        'p1': ['P1'],
        'p2': ['P2'],
        'p_ref': ['PR', '$p2']
    }

    assert apply_flags_by_layers(Config(), TEST_ENTRY_2, ['D3']) == ['D3']
    assert apply_flags_by_layers(Config(presets=PRESETS), TEST_ENTRY_2, ['D3', '$p2']) == ['D3', 'P2']


def test_apply_flags_by_layers():

    PRESETS = {
        'p1': ['P1'],
        'p2': ['P2'],
        'p_ref': ['PR', '$p2']
    }

    LAYER_1 = Layer(name='',
                    files=['**/*2.c', '**/*2.cpp'],
                    flags=['$p2', 'A2'])

    LAYER_2 = Layer(name='',
                    libraries=['lib', 'another_lib'],
                    flags=['A2', 'A3'],
                    drop_flags=['$p_ref', 'A1'])

    LAYER_3_NA = Layer(name='',
                       compilers=['**/*qcc'],
                       flags=['A3', 'A4'])

    LAYER_4 = Layer(name='',
                    files=['**/*2.c', '**/*2.cpp'],
                    flags=['$p1'])

    cfg = Config(presets=PRESETS,
                 layers=[LAYER_1])
    assert apply_flags_by_layers(cfg, TEST_ENTRY_2, ['A1']) == ['A1', 'P2', 'A2']

    cfg.layers = [LAYER_1,
                  LAYER_2]
    assert apply_flags_by_layers(cfg, TEST_ENTRY_2, ['A1']) == ['A2', 'A2', 'A3']

    cfg.layers = [LAYER_1,
                  LAYER_2,
                  LAYER_3_NA,
                  LAYER_4]
    assert apply_flags_by_layers(cfg, TEST_ENTRY_2, ['A1']) == ['A2', 'A2', 'A3', 'P1']


def test_get_relevant_flags():

    assert get_relevant_flags(Config(flags=['A1']), TEST_ENTRY_2) == ['A1']

    assert get_relevant_flags(Config(flags_by_compiler={'gcc': ['A1']}), TEST_ENTRY_2) == ['A1']
    assert get_relevant_flags(Config(flags_by_compiler={'g++': ['A1']}), TEST_ENTRY_2) == []

    assert get_relevant_flags(Config(flags_by_library={'lib': ['A1']}), TEST_ENTRY_2) == ['A1']
    assert get_relevant_flags(Config(flags_by_library={'lib7': ['A1']}), TEST_ENTRY_2) == []

    assert get_relevant_flags(Config(flags_by_file={'**/*.c': ['A1']}), TEST_ENTRY_2) == ['A1']
    assert get_relevant_flags(Config(flags_by_file={'**/*.cpp': ['A1']}), TEST_ENTRY_2) == []

    LAYERS = [LIBRARY_LAYER, QCC_COMPILER_LAYER, FILE_LAYER]
    CFG = Config(flags=['A0'],
                 flags_by_library={'lib': ['A1', '$p1']},
                 layers=LAYERS,
                 presets={'p1': ['P1']})
    flags = get_relevant_flags(CFG, TEST_ENTRY_2)
    assert set(flags) == {'A0', 'A1', 'A2', 'A3', 'P1'}


def test_check_entry():

    assert check_entry(TEST_ENTRY_2, cfg=Config(flags=['A1'])) == ResultsByEntry()
    assert check_entry(TEST_ENTRY_2, cfg=Config(flags=['A1', 'A3'])) == ResultsByEntry(missing=['A3'])


def test_add_to_result():

    STAT_INIT = 2

    res: CheckResult = {}
    stats: CheckStats = {
        ConsistencyLevel.NONE: STAT_INIT,
        ConsistencyLevel.CONTRADICTING: STAT_INIT,
        ConsistencyLevel.INEFFECTIVE: STAT_INIT,
        ConsistencyLevel.ALL: STAT_INIT,
    }

    RES_OF_ENTRY = ResultsByEntry(missing=['a'],
                                  contra=['b', 'c'],
                                  duplicates=['b', 'x', 'y'],
                                  maybe_ineffective_flags=['z'])

    add_to_result(res=res,
                  stats=stats,
                  entry=TEST_ENTRY,   # anything, used for logging only
                  by_entry=RES_OF_ENTRY)

    def in_res(v: str) -> bool:
        return any(f"'{v}'" in k for k in res)

    assert in_res('a')
    assert in_res('b')
    assert in_res('c')
    assert in_res('x')
    assert in_res('y')
    assert in_res('z')

    assert stats[ConsistencyLevel.NONE] == len(RES_OF_ENTRY.missing) + STAT_INIT
    assert stats[ConsistencyLevel.CONTRADICTING] == len(RES_OF_ENTRY.contra) + STAT_INIT
    assert stats[ConsistencyLevel.INEFFECTIVE] == len(RES_OF_ENTRY.maybe_ineffective_flags) + STAT_INIT
    assert stats[ConsistencyLevel.ALL] == len(RES_OF_ENTRY.duplicates) + STAT_INIT

    prev_res = deepcopy(res)
    prev_stats = deepcopy(stats)

    add_to_result(res=res,
                  stats=stats,
                  entry=TEST_ENTRY,   # anything, used for logging only
                  by_entry=ResultsByEntry())

    assert res == prev_res
    assert stats == prev_stats


def test_has_to_fail():

    S0: CheckStats = {
        ConsistencyLevel.NONE: 0,
        ConsistencyLevel.CONTRADICTING: 0,
        ConsistencyLevel.INEFFECTIVE: 0,
        ConsistencyLevel.ALL: 0,
    }

    assert not has_to_fail(S0, ConsistencyLevel.NONE)
    assert not has_to_fail(S0, ConsistencyLevel.ALL)

    S1: CheckStats = {
        ConsistencyLevel.NONE: 1,
        ConsistencyLevel.CONTRADICTING: 0,
        ConsistencyLevel.INEFFECTIVE: 0,
        ConsistencyLevel.ALL: 0,
    }

    assert has_to_fail(S1, ConsistencyLevel.NONE)
    assert has_to_fail(S1, ConsistencyLevel.ALL)

    S2: CheckStats = {
        ConsistencyLevel.NONE: 0,
        ConsistencyLevel.CONTRADICTING: 1,
        ConsistencyLevel.INEFFECTIVE: 0,
        ConsistencyLevel.ALL: 0,
    }

    assert not has_to_fail(S2, ConsistencyLevel.NONE)
    assert has_to_fail(S2, ConsistencyLevel.CONTRADICTING)
    assert has_to_fail(S2, ConsistencyLevel.ALL)

    S3: CheckStats = {
        ConsistencyLevel.NONE: 0,
        ConsistencyLevel.CONTRADICTING: 0,
        ConsistencyLevel.INEFFECTIVE: 1,
        ConsistencyLevel.ALL: 0,
    }

    assert not has_to_fail(S3, ConsistencyLevel.CONTRADICTING)
    assert has_to_fail(S3, ConsistencyLevel.INEFFECTIVE)
    assert has_to_fail(S3, ConsistencyLevel.ALL)

    S4: CheckStats = {
        ConsistencyLevel.NONE: 0,
        ConsistencyLevel.CONTRADICTING: 0,
        ConsistencyLevel.INEFFECTIVE: 0,
        ConsistencyLevel.ALL: 1,
    }

    assert not has_to_fail(S4, ConsistencyLevel.INEFFECTIVE)
    assert has_to_fail(S4, ConsistencyLevel.ALL)


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
