#!/usr/bin/env python3

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
    assert path_wildcards_to_regex('**/a') == '(.+)?/a'
    assert path_wildcards_to_regex('**') == '(.+)?'

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

    assert replace_path_prefix(BASE_DIRS[0], WORK_DIR, BASE_DIRS) == '[...]'
    assert replace_path_prefix(BASE_DIRS[1], WORK_DIR, BASE_DIRS) == '[...]'

    assert replace_path_prefix('/abs/path/to/file', WORK_DIR, BASE_DIRS) == '[...]/to/file'
    assert replace_path_prefix('path/to/file', WORK_DIR, BASE_DIRS) == '[...]/to/file'
    assert replace_path_prefix('other/path/to/file', WORK_DIR, BASE_DIRS) == '/work/other/path/to/file'


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
    '--sysroot=/path/to/toolchain/include',
]

TEST_ENTRY = CdbEntry(file='/path/to/src/file.c',
                      directory='/path/to/build',
                      compiler='/path/to/compiler/gcc',
                      args=TEST_FLAGS,
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

    assert e.file.startswith('[...]/src/')
    assert e.directory == '[...]/build'
    assert e.compiler.startswith('[...]/compiler')
    assert e.out_file.startswith('[...]/build/')

    assert e.args[-3] == '-Irelative/include'
    assert e.args[-2] == '-I[...]/src/include'

    assert e.args[-1] == '--sysroot=[...]/toolchain/include'


def test_is_disabler():

    assert not is_disabler('-I/p/t/x')
    assert not is_disabler('-g')
    assert not is_disabler('-Werror')
    assert is_disabler('-Wno-error')


def test_make_enabler():

    assert make_enabler('-Werror') == '-Werror'
    assert make_enabler('-Wno-error') == '-Werror'


def test_collect_flags_by_keys_basic():

    c = collect_flags_by_keys(['-a', '-b', '-c'])
    assert {'-a', '-b', '-c'} == set(c.keys())
    for k, v in c.items():
        assert v == [k]


def test_collect_flags_by_keys_special():

    c = collect_flags_by_keys(['-O1', '-O2', '-Ww=12', '--Ww=13', '-g3'])
    assert {'-O...', '-Ww=...', '--Ww=...', '-g...'} == set(c.keys())
    assert c['-O...'] == ['-O1', '-O2']
    assert c['-Ww=...'] == ['-Ww=12']
    assert c['-g...'] == ['-g3']


def test_collect_flags_by_keys_disablers():

    c = collect_flags_by_keys(['-fa', '-fno-a', '-fa'])
    assert {'-fa'} == set(c.keys())
    assert c['-fa'] == ['-fa', '-fno-a', '-fa']


def test_get_duplicates():

    assert get_duplicates(['-Wall']) == 0
    assert get_duplicates(['-Wall', '-Wall']) == 1
    assert get_duplicates(['-Wall', '-Wno-all']) == 0
    assert get_duplicates(['-Wall', '-Wno-all'] * 2) == 2


def test_has_contradiction():

    assert not has_contradiction(['-Wall'])
    assert not has_contradiction(['-Wall', '-Wall'])
    assert has_contradiction(['-Wall', '-Wno-all'])
    assert has_contradiction(['-Wno-all', '-Wall'])
    assert has_contradiction(['-Wno-all', '-Wall', '-Wno-all'])


def test_check_consistency_of_collected():

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
    ]

    COLLECTED = collect_flags_by_keys(FLAGS)

    contra, dup = check_consistency_of_collected(COLLECTED)
    assert contra == ['-fomit-frame-pointer']   # TODO add support for -O1 vs -Os
    assert dup == ['-Werror', '-I/p/t/i', '--sysroot=...']


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


def test_check_flag_banned():

    assert not check_flag('!A2', TEST_FLAGS)
    assert check_flag('!A5', TEST_FLAGS)

    assert check_flag('!--A2', TEST_FLAGS)
    assert not check_flag('!-A2', TEST_FLAGS)

    assert not check_flag('!#A[0-9]', TEST_FLAGS)
    assert check_flag('!#A[a-z]', TEST_FLAGS)


def test_check_flags():

    assert check_flags(TEST_ENTRY, [])
    assert check_flags(TEST_ENTRY, ['A2'])
    assert check_flags(TEST_ENTRY, ['A1', '-A2'])

    assert not check_flags(TEST_ENTRY, ['A1', 'A7'])

    assert check_flags(TEST_ENTRY, ['sysroot=/path/to/toolchain/include'])
    assert check_flags(TEST_ENTRY, ['!#A[a-z]', '#A[0-9]'])

    assert check_flags(TEST_ENTRY, ['#^-A[\\d]$'])


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
        flags_by_file={'**/file*.c': ['A2'], '*': ['fail']}))
    assert not check_entry(TEST_ENTRY_2, cfg=Config(
        flags_by_file={'**/file*.c': ['A5'], '*': ['fail']}))


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
