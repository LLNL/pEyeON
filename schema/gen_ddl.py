import argparse
import json
import sys
from pathlib import Path

# Basic mappings; extend as needed
def jsonschema_to_duckdb_type(prop):
    t = prop.get("type")
    fmt = prop.get("format")
    if t == "string":
        if fmt == "date-time":
            return "TIMESTAMP"
        elif fmt == "date":
            return "DATE"
        else:
            return "VARCHAR"
    if t == "integer":
        return "INTEGER"
    if t == "number":
        return "DOUBLE"
    if t == "boolean":
        return "BOOLEAN"
    if t == "array":
        items = prop.get("items", {})
        inner = jsonschema_to_duckdb_type(items)
        # DuckDB LIST requires a concrete inner type, fallback to JSON if unknown
        return f"{inner}[]" if inner else "JSON"
    if t == "object":
        # For nested objects, simplest is a JSON column
        return "JSON"
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
