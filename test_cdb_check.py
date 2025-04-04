#!/usr/bin/env python3

from cdb_check import *


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
