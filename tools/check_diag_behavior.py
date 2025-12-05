#!/usr/bin/env python3

import os
import tempfile
import subprocess
from typing import Dict, List, Optional, Tuple

print('# Check behavior of compiler diagnostic options')
print()

compiler = os.environ.get('CC', default='gcc')

print('Compiler:')
print('```')
r = subprocess.run([compiler, '--version'], capture_output=True, check=False)
print(r.stdout.decode().rstrip())
print('```')
print()

print('## Checks for detecting unused variable')
print()

SRC = """
unsigned foo(void) {
    int unused = 32;
    return 14U;
}
"""

print('Source:')
print('```c')
print(SRC.lstrip().rstrip())
print('```')
print()

src = tempfile.NamedTemporaryFile(suffix='.c', delete_on_close=False)
src.write(SRC.encode())
src.close()


def check_compiler_diag(opts: Optional[List[str]] = None) -> Tuple[bool, str]:
    if not opts:
        opts = []

    out_file = tempfile.NamedTemporaryFile(delete_on_close=False)
    cmd = [compiler] + opts + ['-c', src.name, '-o', out_file.name]
    p = subprocess.run(cmd, capture_output=True, check=False)
    err = p.stderr.decode()
    compiled = bool(p.returncode == 0)
    if 'error:' in err:
        return (compiled, 'E')
    if 'warning:' in err:
        return (compiled, 'W')
    return (compiled, '')


def check_flag_set(flag_set: List[List[str]], table_col_init: Optional[List[str]] = None):
    if not table_col_init:
        table_col_init = []

    res_by_ix: Dict[int, Tuple[bool, str]] = {}

    for i, t in enumerate(flag_set):
        if t and not t[0].startswith('#'):
            res_by_ix[i] = check_compiler_diag(t)

    print()
    to_text(flag_set, res_by_ix)
    print()
    to_table(flag_set, res_by_ix, col_init=table_col_init)
    print()


def to_text(flag_set: List[List[str]], res_by_ix: Dict[int, bool]):

    for i, t in enumerate(flag_set):
        if not t:
            print()
        elif t[0].startswith('#'):
            if i != 0:
                print()
            print(t[0].removeprefix('#').lstrip())
        else:

            res = f'detected ({res_by_ix[i][1]})' if res_by_ix[i][1] else 'not detected'
            print(f'- {res}: `{' '.join(t)}`')


# Create a list of flags to cover all ordered combinations
# I.e. testing for -W1, -W2; -W1, -W3; -W2, -W1
#          results -W1, -W2, -W3, -W1
def collect_flags_in_order(flag_set: List[List[str]],
                           res_by_ix: Dict[int, bool],
                           col_init: List[str]):

    res: List[str] = col_init
    for i, _ in res_by_ix.items():
        flags = flag_set[i]
        ix_in_res = -1
        for f in flags:
            try:
                ix_in_res = res.index(f, ix_in_res + 1)
            except ValueError:
                ix_in_res = len(res)
                res.append(f)
    return res


def to_table(flag_set: List[List[str]],
             res_by_ix: Dict[int, bool],
             col_init: Optional[List[str]] = None):
    if not col_init:
        col_init = []

    flags_in_order = collect_flags_in_order(flag_set, res_by_ix, col_init)
    res_table: List[List[str]] = []

    def cell(val: bool | str) -> str:
        if isinstance(val, bool):
            return 'X' if val else ''
        return val[0] if val else ''

    for i, test_flags in enumerate(flag_set):
        if i not in res_by_ix:
            if res_table and res_table[-1]:
                res_table.append([])
            continue
        row = []
        ix_in_flags = 0
        for f in flags_in_order:
            if ix_in_flags >= len(test_flags):
                row.append(cell(False))
            elif f == test_flags[ix_in_flags]:
                row.append(cell(True))
                ix_in_flags += 1
            else:
                row.append(cell(False))
        res_table.append(row + [cell(res_by_ix[i][1])])

    header = flags_in_order + ['detected']
    header_str_len = [len(h) for h in header]
    row_format = '| ' + ' | '.join("{:^" + str(l) + "}" for l in header_str_len) + ' |'

    header_line = row_format.format(*header)
    dummy_line = ['-'] * len(header_line)
    sep = row_format.format(*dummy_line).replace(' ', '-')

    print(header_line)
    print(sep)

    for line in res_table:
        if line:
            print(row_format.format(*line))
        else:
            print()
            print(header_line)
            print(sep)


print('### Check basic switches')
check_flag_set(
    [
        ['-Wunused'],
        ['-Wall'],
        ['-Wunused', '-Werror'],
        ['-Wall', '-Werror'],
        ['-Werror'],
        ['-Werror=unused'],
    ])


print('### Check generic combinations')
check_flag_set(
    [
        ['-Wall', '-Werror'],
        ['-Wall', '-Werror', '-Wno-all'],
        ['-Wall', '-Werror', '-Wno-error'],
        ['-Werror', '-Wall'],
        ['-Werror', '-Wall', '-Wno-error'],
    ])

print('### Check specific enablers')
check_flag_set(
    [
        ['-Wall', '-Wunused'],
        ['-Wall', '-Wno-unused', '-Wunused'],
        ['-Wall', '-Wunused', '-Wno-all'],
        ['-Wall', '-Werror=unused'],
        ['-Wall', '-Wno-unused', '-Werror=unused'],
        ['-Wall', '-Werror=unused', '-Wno-all'],
    ],
    table_col_init=['-Wall', '-Wno-unused', '-Wunused', '-Werror=unused'])

print('### Check specific disablers')
check_flag_set(
    [
        ['# With -Wno-unused:'],
        ['-Wunused', '-Wno-unused'],
        ['-Wall', '-Wno-unused'],
        ['-Wunused', '-Werror', '-Wno-unused'],
        ['-Wall', '-Werror', '-Wno-unused'],
        ['-Werror', '-Wno-unused'],
        ['-Werror=unused', '-Wno-unused'],
        ['# With -Wno-error=unused:'],
        ['-Wunused', '-Wno-error=unused'],
        ['-Wall', '-Wno-error=unused'],
        ['-Wunused', '-Werror', '-Wno-error=unused'],
        ['-Wall', '-Werror', '-Wno-error=unused'],
        ['-Werror', '-Wno-error=unused'],
        ['-Werror=unused', '-Wno-error=unused'],
    ],
    table_col_init=['-Wunused', '-Wall', '-Werror', '-Werror=unused'])

print('### Check if specific-then-generic sequence')
check_flag_set(
    [
        ['# Beginning with -Wno-unused:'],
        ['-Wno-unused', '-Wunused'],
        ['-Wno-unused', '-Wall'],
        ['-Wno-unused', '-Wunused', '-Werror'],
        ['-Wno-unused', '-Wall', '-Werror'],
        ['-Wno-unused', '-Werror'],
        ['-Wno-unused', '-Werror=unused'],
        ['# With -Wno-error=unused added to the end:'],
        ['-Wno-unused', '-Wunused', '-Wno-error=unused'],
        ['-Wno-unused', '-Wall', '-Wno-error=unused'],
        ['-Wno-unused', '-Wunused', '-Werror', '-Wno-error=unused'],
        ['-Wno-unused', '-Wall', '-Werror', '-Wno-error=unused'],
        ['-Wno-unused', '-Werror', '-Wno-error=unused'],
        ['-Wno-unused', '-Werror=unused', '-Wno-error=unused'],
    ])

check_flag_set(
    [
        ['# Beginning with -Wno-error=unused:'],
        ['-Wno-error=unused', '-Wunused'],
        ['-Wno-error=unused', '-Wall'],
        ['-Wno-error=unused', '-Werror'],
        ['-Wno-error=unused', '-Werror=unused'],
        ['# With -Wno-unused added to the end:'],
        ['-Wno-error=unused', '-Wunused', '-Wno-unused'],
        ['-Wno-error=unused', '-Wall', '-Wno-unused'],
        ['-Wno-error=unused', '-Werror', '-Wno-unused'],
        ['-Wno-error=unused', '-Werror=unused', '-Wno-unused'],
    ])


print('### Check -Werror= behavior')
check_flag_set(
    [
        ['-Werror=unused'],
        ['-Werror=unused', '-Wno-error=unused'],
        ['-Werror=unused', '-Wno-error'],
        ['-Werror=unused', '-Wno-unused'],
        ['-Werror=unused', '-Wno-unused', '-Wno-error=unused'],
        ['# After -Wno-unused:'],
        ['-Wno-unused', '-Werror=unused'],
        ['-Wno-unused', '-Werror=unused', '-Wno-error=unused'],
        ['-Wno-unused', '-Werror=unused', '-Wno-error'],
    ],
    table_col_init=['-Wno-unused', '-Werror=unused', '-Wno-unused'])

print('### Check -Wno-error= behavior')
check_flag_set(
    [
        ['-Wno-error=unused'],
        ['-Wno-error=unused', '-Wno-unused'],
        ['-Wno-error=unused', '-Wunused'],
        ['-Wno-error=unused', '-Werror'],
        ['-Wno-error=unused', '-Werror=unused'],
        ['-Wno-error=unused', '-Wunused', '-Werror=unused'],
        ['# After -Wunused:'],
        ['-Wunused', '-Wno-error=unused'],
        ['-Wunused', '-Wno-error=unused', '-Werror'],
    ],
    table_col_init=['-Wunused'])
