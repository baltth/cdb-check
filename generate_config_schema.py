#!/usr/bin/env python3

from json import dumps
from dataclasses import dataclass
from dataclasses_jsonschema import JsonSchemaMixin
from cdb_check import Config

@dataclass
class ConvertibleConfig(Config, JsonSchemaMixin):
    pass

schema = ConvertibleConfig.json_schema()
del schema['properties']['extra']
schema['description'] = 'JSON schema for cdb-check configuration'

with open("config.schema.json", "w") as f:
    f.write(dumps(schema, indent=2))
