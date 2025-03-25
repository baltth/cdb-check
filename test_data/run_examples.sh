#!/usr/bin/env bash
set -eu

SCRIPT_DIR=$(dirname $(realpath ${0}))
pushd ${SCRIPT_DIR}/..

echo "Basic check ..."
./cdb_check.py test_data/compile_commands.json -f Wall I/path/to/project/prj/include
echo "Check failure ..."
./cdb_check.py test_data/compile_commands.json -f pedantic || true
echo "Dump file ..."
./cdb_check.py test_data/compile_commands.json -u /path/to/project/prj/src/file4.c -d
echo "Dump with base dirs ..."
./cdb_check.py test_data/compile_commands.json -b /path/to/project/prj -u file4.c -d
echo "Wildcard input ..."
./cdb_check.py test_data/compile_commands.json -b /path/to/project/prj -u '*.cpp' -f pedantic Wall Wextra
echo "Config file ..."
./cdb_check.py -c test_data/config.json test_data/compile_commands.json
echo "Check C++ standard..."
./cdb_check.py -c test_data/config.json test_data/compile_commands.json -u '*.cpp' -f std=c++11
echo "Check C standard ..."
./cdb_check.py -c test_data/config.json test_data/compile_commands.json -u '*.c' -f std=c11
echo "Check library options ..."
./cdb_check.py -c test_data/config.json test_data/compile_commands.json -u 'src/lib/*' -f pedantic DSOME_DEFINE=0

popd
