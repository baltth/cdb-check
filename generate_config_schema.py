#!/usr/bin/env python3

from copy import deepcopy
from json import dumps
from dataclasses import dataclass, field
from typing import List, Dict, Any
from dataclasses_jsonschema import JsonSchemaMixin
import cdb_check

# New config types are derived here to avoid introducing
# dependency to dataclasses_jsonschema to the main code.


@dataclass
class Layer(cdb_check.Layer, JsonSchemaMixin):
    pass


@dataclass
class Config(cdb_check.Config, JsonSchemaMixin):
    layers: List[Layer] = field(default_factory=list)


# Generate base of schema
schema = Config.json_schema()

# Remove/replace some properties
del schema['properties']['extra']
del schema['definitions']['Layer']['description']
schema['description'] = 'JSON schema for cdb-check configuration'

# Use definitions and references 'Strings' and 'StringsMap' to remove redundancy

strings_def = deepcopy(schema['properties']['flags'])
strings_map_def = deepcopy(schema['properties']['flags_by_compiler'])


def ref(name: str) -> Dict[str, str]:
    return {'$ref': f'#/definitions/{name}'}


def reduce_schema(s: Dict[str, Any]):

    def reduce(d: Dict[str, Any], to_reduce: Dict[str, Any], ref_type: str):
        for k, v in d.items():
            if v == to_reduce:
                d[k] = ref(ref_type)

    if s['type'] != 'object':
        return
    reduce(s['properties'], strings_def, 'Strings')
    reduce(s['properties'], strings_map_def, 'StringsMap')

    if 'definitions' in s.keys():
        for v in s['definitions'].values():
            reduce_schema(v)


reduce_schema(schema)

strings_map_def['additionalProperties'] = ref('Strings')
schema['definitions']['Strings'] = strings_def
schema['definitions']['StringsMap'] = strings_map_def

# Write to file

with open("config.schema.json", "w") as f:
    f.write(dumps(schema, indent=2))
