cdb-check
===

![test](https://github.com/baltth/cdb-check/actions/workflows/main.yml/badge.svg)

Tool to verify C/C++ build configuration by checking the
_[compile database](https://clang.llvm.org/docs/JSONCompilationDatabase.html)_,
i.e. `compile_commands.json` files generated by the build system.

This tool helps to verify the presence of specific compile options,
useful to ensure consistency of different build configurations.
Use it when a compile DB is available, e.g. when using
[CMake](https://cmake.org) or [LLVM](https://clang.llvm.org).

> To configure CMake to create a compile DB see
> [CMAKE_EXPORT_COMPILE_COMMANDS](https://cmake.org/cmake/help/latest/variable/CMAKE_EXPORT_COMPILE_COMMANDS.html)

## Installation, dependencies

This tool is intended to be a _simple utility script,_ I do not plan to create
a package nor to add an installer. Just download and use it.

Dependencies: _Python 3_ and nothing else. Tested on Ubuntu 24.04 with
a standard _Python 3.12.3_ installation

## Usage

See `./cdb-check-py -h`

## Features

- check if a user-defined compile option set is present in the CDB
- filter compile units to check, with support for simple wildcards
- filter compilations by logical libraries, i.e. filter by
  output file paths generated by the build system
- remove specified path prefixes from the paths and and compile arguments
  (e.g. project path, build folder or sysroot) to make configuration easier
- configurable with config file and/or CLI arguments
  - CLI arguments are extending the configuration if present
    to create custom scenarios easily
  - automatically applied flag presets in config file
- check the consistency of the CDB, e.g. look for flag duplicates
  and contradicting flags
- dump the loaded and filtered CDB for debugging

### How to use?

Consider a project built with CMake like
```
prj
|-include
| +-...
+-src
  |-lib
  | |-file1.cpp   # in cmake target 'lib'
  | +-file2.cpp   # in cmake target 'lib'
  |-file3.cpp     # in cmake target 'prj'
  +-file4.c       # in cmake target 'prj'
```
This will generate a compile DB like
```json
[
  {
    "directory": "/path/to/project/prj/build",
    "command": "/usr/bin/c++ -DLIB_DEFINE=1 -I/path/to/project/prj/include -g -Wall -Wextra -pedantic -std=c++11 -o CMakeFiles/lib.dir/src/lib/file1.cpp.o -c /path/to/project/prj/src/lib/file1.cpp",
    "file": "/path/to/project/prj/src/lib/file1.cpp"
  },
  {
    "directory": "/path/to/project/prj/build",
    "command": "/usr/bin/c++ -DLIB_DEFINE=1 -I/path/to/project/prj/include -g -Wall -Wextra -std=c++11 -o CMakeFiles/lib.dir/src/lib/file2.cpp.o -c /path/to/project/prj/src/lib/file2.cpp",
    "file": "/path/to/project/prj/src/lib/file2.cpp"
  },
  {
    "directory": "/path/to/project/prj/build",
    "command": "/usr/bin/c++ -I/path/to/project/prj/include -g -Wall -Wextra -pedantic -std=c++11 -o CMakeFiles/prj.dir/src/file3.cpp.o -c /path/to/project/prj/src/file3.cpp",
    "file": "/path/to/project/prj/src/file3.cpp"
  },
  {
    "directory": "/path/to/project/prj/build",
    "command": "/usr/bin/gcc -I/path/to/project/prj/include -g -Wall -Wextra -pedantic -std=c11 -o CMakeFiles/prj.dir/src/file4.c.o -c /path/to/project/prj/src/file4.c",
    "file": "/path/to/project/prj/src/file4.c"
  }
]
```

Let's assume this file is at `test_data/cdb.json`.
Some _common use cases_ for the tool:

> Note: all examples below can be run by the script `test_data/run_examples.sh`

- Check if all _compiled files use_ `-Wall` and the proper include path:
  ```sh
  $ ./cdb_check.py test_data/cdb.json -f Wall I/path/to/project/prj/include

  Checking 4 entries(s) ...
  OK
  ```
  > Note that the leading `-` is removed from the flag arguments.

- Now check if all files use `-pedantic`:
  ```sh
  $ ./cdb_check.py test_data/cdb.json -f pedantic

  Checking 4 entries(s) ...
  /path/to/project/prj/src/file4.c: missing flag 'pedantic'
  ```
  Oops... it failed, but this is the goal of the tool.
  Let's take a closer look of this compilation!

- _Dump the details_ of a file:
  ```sh
  $ ./cdb_check.py test_data/cdb.json -u /path/to/project/prj/src/file4.c -d

  Checking 1 matching entries(s) ...
  /path/to/project/prj/src/file4.c
    compiled with /usr/bin/gcc
    to file /path/to/project/prj/build/CMakeFiles/prj.dir/src/file4.c.o
    with args
      -I/path/to/project/prj/include
      -g
      -Wall
      -Wextra
      -std=c11
  OK
  ```

- _Simplify paths_ by removing the prefix project path to reduce noise:
  ```sh
  $ ./cdb_check.py test_data/cdb.json -b /path/to/project/prj -u file4.c -d

  Checking 1 matching entries(s) ...
  [...]/src/file4.c
    compiled with /usr/bin/gcc
    to file [...]/build/CMakeFiles/prj.dir/src/file4.c.o
    with args
      -I[...]/include
      -g
      -Wall
      -Wextra
      -std=c11
  OK
  ```
  This also applies to file arguments - the option `-u file2.cpp`
  could be `-u src/lib/file2.cpp` but the full path won't work.
  Similarly the flag arguments are simplified - to check the includes
  use `-f I[...]/include`.

- _Use wildcards_ for files to check:
  ```sh
  $ ./cdb_check.py test_data/cdb.json -b /path/to/project/prj -u '*.cpp' -f pedantic Wall Wextra

  Checking 3 matching entries(s) ...
  OK
  ```

- Filter by _logical libraries._ E.g. to check files compiled to
  _CMake target `lib`:_
  ```sh
  $ ./cdb_check.py test_data/cdb.json -b /path/to/project/prj -l lib -f DLIB_DEFINE=1

  Checking 2 matching entries(s) ...
  OK
  ```

#### Using a config file

- _Create a configuration_ to get rid of CLI options:
  create a file `cfg.json` with contents
  ```json
  {
    "base_dirs": ["/path/to/prj"],
    "flags": ["Wall", "Wextra", "-g", "I[...]/include"]
  }
  ```
  and use this on the CLI:
  ```sh
  $ ./cdb_check.py -c test_data/cfg.json test_data/cdb.json

  Checking 4 entries(s) ...
  OK
  ```

- _Use configurations_ as a baseline for _specialization_ - keep
  common settings in config and apply specific options on CLI
  ```sh
  # Each command runs common checks and
  # - check C++ standard
  ./cdb_check.py -c test_data/cfg.json test_data/cdb.json -u '*.cpp' -f std=c++11
  # - check C standard
  ./cdb_check.py -c test_data/cfg.json test_data/cdb.json -u '*.c' -f std=c11
  # - check for '-pedantic' and definitions in library
  ./cdb_check.py -c test_data/cfg.json test_data/cdb.json -l lib -f DLIB_DEFINE=1
  ```

#### Presets in configuration

Consider a multi platform project, e.g. compiled to x86 and _aarch64._
The latter will produce a different `compile_commands.json`,
e.g. like `test_data/cdb_aarch64.json`. The config file can be used to
declare presets based on the compiler:
```json
{
  "base_dirs": ["/path/to/project/prj", "/path/to/toolchains"],
  "flags": ["Wall", "Wextra", "g", "I[...]/include"],
  "flags_by_compiler": {
    "aarch64-oe-linux-*": ["finline-limit=64", "D__ARM_PCS_VFP"]
  }
}
```

This will add the extra flags the the checked set for
the matching compilations. The same can be used to differentiate
by language:
```json
  "flags_by_compiler": {
    "c++": ["std=c++11"],
    "gcc": ["std=c11"],
  }
```

This matching is a _first-fit matching_ with a special default key `*`
for unmatched compilers. This can be used even to enforce
the specification with any custom non-existing flag:
```json
  "flags_by_compiler": {
    "aarch64-oe-linux-*": ["finline-limit=64", "D__ARM_PCS_VFP"],
    "*": ["fail_as_compiler_has_no_preset"]
  }
```

Presets for 'libraries' or compile units can be added by the same method:
```json
  "flags_by_library": {
    "lib": ["DLIB_DEFINE=1", "pedantic"]
  },
  "flags_by_file": {
    "*.c": ["std=c11"],
    "*.cpp": ["std=c++11"]
  }
```

Use _verbose mode_ with `-v` option to get details about
the effective configuration and matching results. This will produce
output like
```
cdb-check - running in verbose mode
Configuration:
{'base_dirs': ['/path/to/project/prj', '/path/to/toolchains'], 'libraries': [], 'compile_units': [], 'flags': ['Wall', 'Wextra', 'g', 'I[...]/include'], 'verbose': True, 'flags_by_compiler': {'aarch64-oe-linux-*': ['finline-limit=64', 'D__ARM_PCS_VFP']}, 'flags_by_library': {'lib': ['DLIB_DEFINE=1', 'pedantic']}, 'flags_by_file': {'*.c': ['std=c11'], '*.cpp': ['std=c++11', 'pedantic']}, 'extra': {'input': 'test_data/cdb_aarch64.json', 'config': 'test_data/cfg_complex_preset.json', 'dump': False}}
Checking test_data/cdb_aarch64.json ...
Checking 4 entries(s) ...
Entry [...]/src/lib/file1.cpp ...
Checking for flag preset by compiler ...
  ... matching: aarch64-oe-linux-*
Checking for flag preset by library ...
  ... matching: lib
Checking for flag preset by file name ...
  ... matching: *.cpp
Expecting Wall Wextra g I[...]/include finline-limit=64 D__ARM_PCS_VFP DLIB_DEFINE=1 pedantic std=c++11
All flags found
...
```

#### Property matching methods

Compilers and compile units are matched with
[pathlib.PurePath.match()](https://docs.python.org/3/library/pathlib.html#pathlib.PurePath.match).
This supports
  - `*` for parts of a file or directory segment or a full segment
  - `?` for one non-separator character
  - `[seq]` for one character in 'seq'
  - `[!seq]` for one character _not_ in 'seq'

Note that _recursive wildcards_ (`**`) are not supported.
The path is matched from the left if absolute, otherwise
it's matched from the right.

Libraries are matched with specialized substring lookups.
A compilation is considered part of the library `LIB`
if the path of the output file contains either
- `/LIB/`, e.g. `/path/to/build/LIB/file.c.o`, or
- `CMakeFiles/LIB.dir/`, e.g. `/path/to/build/CMakeFiles/LIB.dir/file.c.o`

> More specializations can be added later for
> build system generators other than CMake. In the meantime
> just simply use the pattern you have. 

Flag matching supports to pass flags without the leading `-` prefix.
This helps to pass CLI args easier. Because of this flag matching works like
- match the flag as-is if it's first character is `-`, or
- check if `-FLAG` or `--FLAG` is present.


### Configuration

An overview of configuration options for processing:

Option        | from CLI | from config file | Description
--------------|----------|------------------|-----------------------------
Basic flags   | Y        | Y                | Common flags to check on all
Flag presets  | N        | Y                | Specific flags, additional to the common set
Base dirs     | Y        | Y                | Directory prefixes to remove
Compile units | Y        | Y                | Scope check to the specified files
Libraries     | Y        | Y                | Scope check to the specified logical libraries

All above but flag presets are lists. Options can be provided
from CLI and config file at the same time, in this case the options are
appended, i.e. both CLI and file options are applied.

Here comes some pseudocode for the details.
A CDB is loaded and prepared:
```py
prefixes_to_remove = (cfg.base_dirs + args.base_dirs)
for entry in cdb:
    separate_arguments_to_properties(entry)
    remove_path_prefixes(entry, prefixes_to_remove)
```

The scope of compilations to check is determined:
```py
# scoping properties, default to all:
libs_to_check = (cfg.compile_units + args.compile_units) or CHECK_ALL
cus_to_check = (cfg.compile_units + args.compile_units) or CHECK_ALL

scope_of_check = []
for entry in cdb:
    if match(entry, libs_to_check) and match(entry, cus_to_check):
      scope_of_check.append(entry)
```

The flags to check for a single compilation are:
```py
# basic flags
flags = cfg.flags + args.flags
# flags by compiler
flags += select_preset(cfg.flags_by_compiler, entry)
# flags by library
flags += select_preset(cfg.flags_by_library, entry)
# flags by compile unit name
flags += select_preset(cfg.flags_by_file, entry)
```

where `select_preset` is a _first-fit_ method with
fallback to the wildcard `*` preset:
```py
for p in presets:  
    if match(entry, p):
        return presets[p]   # select 'p' on match, or
if '*' presets:
    return presets['*']     # select default if present, or
else:
    return []               # select none
```

### Planned features:

- builtin library patterns for non-cmake build system generators
- maybe add a minimalistic support for makefiles
