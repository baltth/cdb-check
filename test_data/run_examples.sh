#!/usr/bin/env bash
set -eu

SCRIPT_DIR=$(dirname $(realpath ${0}))
pushd ${SCRIPT_DIR}/..

echo "Basic check ..."
./cdb_check.py test_data/cdb.json -f Wall I/path/to/project/prj/include
echo "Check failure ..."
./cdb_check.py test_data/cdb.json -f pedantic || true
echo "Dump file ..."
./cdb_check.py test_data/cdb.json -u /path/to/project/prj/src/file4.c -d
echo "Dump with base dirs ..."
./cdb_check.py test_data/cdb.json -b /path/to/project/prj -u file4.c -d
echo "Wildcard input ..."
./cdb_check.py test_data/cdb.json -b /path/to/project/prj -u '*.cpp' -f pedantic Wall Wextra
echo "Logical libraries ..."
./cdb_check.py test_data/cdb.json -b /path/to/project/prj -l lib -f DLIB_DEFINE=1

echo "Config file ..."
./cdb_check.py -c test_data/cfg.json test_data/cdb.json
echo "Check C++ standard..."
./cdb_check.py -c test_data/cfg.json test_data/cdb.json -u '*.cpp' -f std=c++11
echo "Check C standard ..."
./cdb_check.py -c test_data/cfg.json test_data/cdb.json -u '*.c' -f std=c11
echo "Check library options ..."
./cdb_check.py -c test_data/cfg.json test_data/cdb.json -l lib -f pedantic DLIB_DEFINE=1

echo "Config file with compiler presets ..."
echo "- x86 ..."
./cdb_check.py -c test_data/cfg_comp_preset.json test_data/cdb.json
echo "- aarch64 ..."
./cdb_check.py -c test_data/cfg_comp_preset.json test_data/cdb_aarch64.json

echo "Config file with complex presets ..."
echo "- x86 ..."
./cdb_check.py -v -c test_data/cfg_complex_preset.json test_data/cdb.json
echo "- aarch64 ..."
./cdb_check.py -v -c test_data/cfg_complex_preset.json test_data/cdb_aarch64.json

popd
