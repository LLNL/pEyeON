import argparse
import json
import sys
from pathlib import Path

from typing import Any, Dict, Optional

SCALAR_TYPES = {"string", "integer", "number", "boolean"}

def resolve_ref(schema: Dict[str, Any], ref: str) -> Optional[Dict[str, Any]]:
    """
    Resolve local JSON Schema refs like '#/$defs/Foo' or '#/definitions/Foo'.
    Returns the referenced schema dict or None if not found.
    """
    if not ref.startswith("#/"):
        # External refs not supported in this simple resolver
        return None
    path = ref[2:].split("/")  # remove '#/' and split
    node: Any = schema
    for key in path:
        if isinstance(node, dict) and key in node:
            node = node[key]
        else:
            return None
    return node if isinstance(node, dict) else None

def is_scalar_jsonschema_type(prop: Dict[str, Any]) -> bool:
    """Return True if prop is a plain scalar type, possibly with format."""
    t = prop.get("type")
    # One-of unions, anyOf, etc are not treated as scalar here
    return t in SCALAR_TYPES

def jsonschema_scalar_to_duckdb_type(prop: Dict[str, Any]) -> str:
    """Map scalar JSON Schema types to DuckDB types."""
    t = prop.get("type")
    fmt = prop.get("format")
    if t == "string":
        if fmt == "date-time":
            return "TIMESTAMP"
        if fmt == "date":
            return "DATE"
        # optionally, check for "time", "uuid", "email" formats if you want specialized types
        return "VARCHAR"
    if t == "integer":
        return "INTEGER"
    if t == "number":
        return "DOUBLE"
    if t == "boolean":
        return "BOOLEAN"
    # Fallback for unexpected
    return "JSON"

def jsonschema_to_duckdb_type(prop: Dict[str, Any], root_schema: Optional[Dict[str, Any]] = None) -> str:
    """
    Recursively map a JSON Schema property to a DuckDB type.
    - Arrays of scalars -> element_type[]
    - Arrays of complex types -> JSON
    - Objects -> JSON
    - $ref resolved against root_schema
    """
    if prop is None:
        return "JSON"

    # Resolve $ref if present
    if "$ref" in prop and root_schema:
        resolved = resolve_ref(root_schema, prop["$ref"])
        if resolved:
            prop = resolved

    # Handle explicit type as list (union) or anyOf/oneOf; default to JSON
    t = prop.get("type")
    if isinstance(t, list):
        # Union types, choose first scalar if available, else JSON
        for candidate in t:
            if candidate in SCALAR_TYPES:
                return jsonschema_scalar_to_duckdb_type({"type": candidate})
        return "JSON"

    # Scalar types
    if t in SCALAR_TYPES:
        return jsonschema_scalar_to_duckdb_type(prop)

    # Arrays
    if t == "array":
        items = prop.get("items")
        if not items:
            # Unknown element type, default to JSON to be safe
            return "JSON"
        # Resolve nested refs inside items
        if isinstance(items, dict) and "$ref" in items and root_schema:
            resolved_items = resolve_ref(root_schema, items["$ref"])
            if resolved_items:
                items = resolved_items

        # If items is a schema dict and a scalar, make a list of that type
        if isinstance(items, dict) and is_scalar_jsonschema_type(items):
            inner = jsonschema_scalar_to_duckdb_type(items)
            return f"{inner}[]"
        # If items describe objects, unions, or nested arrays, store as JSON
        return "JSON"

    # Objects, nested structures, or missing type
    if t == "object" or ("properties" in prop) or ("additionalProperties" in prop):
        # You could alternatively flatten here, but JSON is the simplest and safest
        return "JSON"

    # Formats like "date-time" with no explicit type occasionally appear, safeguard:
    if "format" in prop and t is None:
        return jsonschema_scalar_to_duckdb_type({"type": "string", "format": prop["format"]})

    # Fallback
    return "JSON"

def generate_ddl(schema_path: Path, table_name: str) -> str:
    schema = json.loads(Path(schema_path).read_text())
    props = schema.get("properties", {})
    required = set(schema.get("required", []))

    columns = []
    for name, prop in props.items():
        col_type = jsonschema_to_duckdb_type(prop)
        # DuckDB does not enforce NOT NULL at creation for JSON ingestion,
        # but you can add NOT NULL where appropriate
        nullability = "NOT NULL" if name in required else ""
        columns.append(f'"{name}" {col_type} {nullability}'.strip())

    ddl = f"CREATE OR REPLACE TABLE {table_name} (\n  " + ",\n  ".join(columns) + "\n);"
    return ddl


def main(argv=None):
  parser = argparse.ArgumentParser(
    prog="gen_ddl.py",
    description="Generate DuckDB DDL from a JSON Schema."
  )
  parser.add_argument(
    "--schema",
    required=True,
    type=Path,
    help="Path to the JSON Schema file."
  )
  parser.add_argument(
    "--table",
    required=True,
    help="Target table name to create."
  )
  parser.add_argument(
    "--out",
    required=True,
    type=Path,
    help="Output .sql file to write the generated DDL."
  )

  args = parser.parse_args(argv)

  # Read schema file if needed by your implementation
  # schema_json = args.schema.read_text(encoding="utf-8")

  ddl = generate_ddl(args.schema, args.table)

  args.out.write_text(ddl, encoding="utf-8")
  print(f"Wrote DDL to {args.out}")

if __name__ == "__main__":
  main()
