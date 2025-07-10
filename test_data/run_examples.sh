#!/usr/bin/env bash
set -eu

SCRIPT_DIR=$(dirname $(realpath ${0}))
pushd ${SCRIPT_DIR}/..

echo "---"
echo "Basic check ..."
echo "---"
./cdb_check.py test_data/cdb.json -f Wall I/path/to/project/prj/include
echo "---"
echo "Check failure ..."
echo "---"
./cdb_check.py test_data/cdb.json -f pedantic || true
echo "---"
echo "Dump file ..."
echo "---"
./cdb_check.py test_data/cdb.json -u /path/to/project/prj/src/file4.c -d
echo "---"
echo "Dump with base dirs ..."
echo "---"
./cdb_check.py test_data/cdb.json -b /path/to/project/prj -u file4.c -d
echo "---"
echo "Wildcard input ..."
echo "---"
./cdb_check.py test_data/cdb.json -b /path/to/project/prj -u '**/*.cpp' -f pedantic Wall Wextra
echo "---"
echo "Logical libraries ..."
echo "---"
./cdb_check.py test_data/cdb.json -b /path/to/project/prj -l lib -f DLIB_DEFINE=1

echo "---"
echo "Config file ..."
echo "---"
./cdb_check.py -c test_data/cfg.json test_data/cdb.json
echo "---"
echo "Check C++ standard..."
echo "---"
./cdb_check.py -c test_data/cfg.json test_data/cdb.json -u '**/*.cpp' -f std=c++11
echo "---"
echo "Check C standard ..."
echo "---"
./cdb_check.py -c test_data/cfg.json test_data/cdb.json -u '**/*.c' -f std=c11
echo "---"
echo "Check library options ..."
echo "---"
./cdb_check.py -c test_data/cfg.json test_data/cdb.json -l lib -f pedantic DLIB_DEFINE=1

echo "---"
echo "Config file with compiler settings ..."
echo "---"
echo "- x86 ..."
echo "---"
./cdb_check.py -c test_data/cfg_compiler.json test_data/cdb.json
echo "---"
echo "- aarch64 ..."
echo "---"
./cdb_check.py -c test_data/cfg_compiler.json test_data/cdb_aarch64.json

echo "---"
echo "Config file with complex 'choose one' settings ..."
echo "---"
echo "- x86 ..."
echo "---"
./cdb_check.py -v -c test_data/cfg_complex.json test_data/cdb.json
echo "---"
echo "- aarch64 ..."
echo "---"
./cdb_check.py -v -c test_data/cfg_complex.json test_data/cdb_aarch64.json

echo "---"
echo "Config file with presets and layers, summarized ..."
echo "---"
# expected to fail
! ./cdb_check.py -s -c test_data/cfg_layers.json test_data/cdb_layers.json

echo "---"
popd
