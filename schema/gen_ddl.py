#!/usr/bin/env python3
"""
Generate DuckDB DDL from JSON Schema with x-duckdb-* hints.
"""
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Optional


class DuckDBDDLGenerator:
    def __init__(self, schema: Dict[str, Any]):
        self.schema = schema
        self.tables: Dict[str, Dict[str, str]] = {}  # table_name -> {col_name: col_def}
        self.foreign_keys: Dict[str, List[str]] = {}  # table_name -> list of FK constraints
        self.table_pks: Dict[str, str] = {}  # table_name -> pk column name
        
    def generate(self) -> str:
        """Generate complete DDL for the schema."""
        # Process root object
        root_table = self.schema.get('x-duckdb-table', 'root')
        root_pk = self.schema.get('x-duckdb-pk')
        
        self._process_object(
            self.schema,
            table_name=root_table,
            parent_table=None,
            parent_pk=None,
            path='$'
        )
        
        # Build DDL statements
        ddl_statements = []
        
        for table_name, columns in self.tables.items():
            ddl = f"CREATE TABLE {table_name} (\n"
            
            # Add columns
            col_defs = list(columns.values())
            ddl += "  " + ",\n  ".join(col_defs)
            
            # Add foreign keys
            if table_name in self.foreign_keys:
                ddl += ",\n  " + ",\n  ".join(self.foreign_keys[table_name])
            
            ddl += "\n);"
            ddl_statements.append(ddl)
        
        return "\n\n".join(ddl_statements)
    
    def _ensure_table(self, table_name: str):
        """Ensure table exists in tables dict."""
        if table_name not in self.tables:
            self.tables[table_name] = {}
    
    def _add_column(self, table_name: str, col_name: str, col_def: str):
        """Add a column to a table, avoiding duplicates."""
        self._ensure_table(table_name)
        if col_name not in self.tables[table_name]:
            self.tables[table_name][col_name] = col_def
    
    def _add_fk(self, table_name: str, fk_def: str):
        """Add a foreign key constraint."""
        if table_name not in self.foreign_keys:
            self.foreign_keys[table_name] = []
        if fk_def not in self.foreign_keys[table_name]:
            self.foreign_keys[table_name].append(fk_def)
    
    def _process_object(
        self,
        obj_schema: Dict[str, Any],
        table_name: str,
        parent_table: Optional[str],
        parent_pk: Optional[str],
        path: str
    ):
        """Process an object schema and generate table definition."""
        self._ensure_table(table_name)
        
        # Add PK if specified
        pk = obj_schema.get('x-duckdb-pk')
        if pk:
            self.table_pks[table_name] = pk
            pk_type = obj_schema.get('x-duckdb-pk-type', 'VARCHAR')
            self._add_column(table_name, pk, f"{pk} {pk_type} PRIMARY KEY")
        
        # Add parent FK if this is a child table
        parent_fk = obj_schema.get('x-duckdb-fk')
        if parent_fk and parent_table and parent_pk:
            self._add_column(table_name, parent_fk, f"{parent_fk} VARCHAR")
            self._add_fk(table_name, f"FOREIGN KEY ({parent_fk}) REFERENCES {parent_table}({parent_pk})")
        
        # Handle oneOf with discriminator (polymorphic metadata)
        if 'oneOf' in obj_schema:
            for variant in obj_schema['oneOf']:
                variant_table = variant.get('x-duckdb-table')
                
                if variant_table and '$ref' in variant:
                    ref_schema = self._resolve_ref(variant['$ref'])
                    
                    # Process variant as separate table with FK back to parent
                    self._process_object(
                        ref_schema,
                        table_name=variant_table,
                        parent_table=table_name,
                        parent_pk=pk,
                        path=f"{path}.{variant_table}"
                    )
            return  # Don't process properties for polymorphic parent
        
        # Process properties
        properties = obj_schema.get('properties', {})
        required = obj_schema.get('required', [])
        
        for prop_name, prop_schema in properties.items():
            # Skip if property is the PK (already added)
            if prop_name == pk:
                continue
                
            # Handle $ref
            if '$ref' in prop_schema:
                ref_schema = self._resolve_ref(prop_schema['$ref'])
                # Merge ref with any overrides in prop_schema
                merged = {**ref_schema}
                for k, v in prop_schema.items():
                    if k != '$ref':
                        merged[k] = v
                prop_schema = merged
            
            self._process_property(
                prop_name,
                prop_schema,
                table_name,
                pk,
                path,
                is_required=(prop_name in required)
            )
    
    def _process_property(
        self,
        prop_name: str,
        prop_schema: Dict[str, Any],
        table_name: str,
        table_pk: Optional[str],
        path: str,
        is_required: bool
    ):
        """Process a single property."""
        prop_type = prop_schema.get('type')
        
        # Check for oneOf with discriminator (polymorphic relationship)
        if 'oneOf' in prop_schema and 'x-duckdb-discriminator' in prop_schema:
            # Process each variant as a separate table
            for variant in prop_schema['oneOf']:
                variant_table = variant.get('x-duckdb-table')
                variant_pk = variant.get('x-duckdb-pk')
                
                if variant_table and '$ref' in variant:
                    ref_schema = self._resolve_ref(variant['$ref'])
                    
                    # Merge variant annotations into ref_schema
                    ref_schema = {**ref_schema}
                    if variant_pk:
                        ref_schema['x-duckdb-pk'] = variant_pk
                    
                    # Process variant as separate table with FK back to parent
                    ref_schema['x-duckdb-fk'] = f"{table_name[:-1]}_uuid" if table_name.endswith('s') else f"{table_name}_uuid"
                    
                    self._process_object(
                        ref_schema,
                        table_name=variant_table,
                        parent_table=table_name,
                        parent_pk=table_pk,
                        path=f"{path}.{prop_name}.{variant_table}"
                    )
            return  # Don't add column for polymorphic property
        
        # Check for separate table hint
        if 'x-duckdb-table' in prop_schema:
            child_table = prop_schema['x-duckdb-table']
            child_fk = prop_schema.get('x-duckdb-fk', f"{table_name}_id")
            child_pk = prop_schema.get('x-duckdb-pk')
            
            if prop_type == 'array':
                items_schema = prop_schema.get('items', {})
                
                # Resolve $ref in items
                if '$ref' in items_schema:
                    items_schema = self._resolve_ref(items_schema['$ref'])
                
                if items_schema.get('type') == 'object':
                    # Array of objects -> separate table
                    # Add auto-increment PK if specified
                    if child_pk:
                        items_schema = {**items_schema, 'x-duckdb-pk': child_pk}
                    
                    items_schema['x-duckdb-fk'] = child_fk
                    
                    self._process_object(
                        items_schema,
                        table_name=child_table,
                        parent_table=table_name,
                        parent_pk=table_pk,
                        path=f"{path}.{prop_name}[]"
                    )
                else:
                    # Array of primitives -> separate table with value column
                    value_col = prop_schema.get('x-duckdb-value-column', 'value')
                    self._ensure_table(child_table)
                    self._add_column(child_table, child_fk, f"{child_fk} VARCHAR")
                    self._add_column(child_table, value_col, f"{value_col} VARCHAR")
                    
                    if table_pk:
                        self._add_fk(child_table, f"FOREIGN KEY ({child_fk}) REFERENCES {table_name}({table_pk})")
            
            return
        
        # Check for flatten hint
        if prop_schema.get('x-duckdb-flatten'):
            if prop_type == 'object':
                # Flatten nested object properties into current table
                nested_props = prop_schema.get('properties', {})
                nested_required = prop_schema.get('required', [])
                
                for nested_name, nested_schema in nested_props.items():
                    # Use flattened naming: parent_child
                    # flat_name = f"{prop_name}_{nested_name}"
                    flat_name = nested_name
                    self._process_property(
                        flat_name,
                        nested_schema,
                        table_name,
                        table_pk,
                        f"{path}.{prop_name}",
                        is_required=(nested_name in nested_required)
                    )
            return
        
        # Check for array hint (store as DuckDB array)
        if prop_schema.get('x-duckdb-array') and prop_type == 'array':
            items_schema = prop_schema.get('items', {})
            item_type = self._map_type(items_schema.get('type', 'string'))
            column_def = f"{prop_name} {item_type}[]"
            if not is_required:
                column_def += " DEFAULT NULL"
            self._add_column(table_name, prop_name, column_def)
            return
        
        # Check for JSON storage hint
        if prop_schema.get('x-duckdb-json'):
            column_def = f"{prop_name} JSON"
            if not is_required:
                column_def += " DEFAULT NULL"
            self._add_column(table_name, prop_name, column_def)
            return
        
        # Handle regular types
        if prop_type in ['string', 'integer', 'number', 'boolean']:
            sql_type = self._map_type(prop_type)
            
            # Check for enum (becomes VARCHAR)
            if 'enum' in prop_schema:
                sql_type = 'VARCHAR'
            
            column_def = f"{prop_name} {sql_type}"
            if not is_required:
                column_def += " DEFAULT NULL"
            self._add_column(table_name, prop_name, column_def)
        
        elif prop_type == 'object':
            # Nested object without hints -> store as JSON
            column_def = f"{prop_name} JSON"
            if not is_required:
                column_def += " DEFAULT NULL"
            self._add_column(table_name, prop_name, column_def)
        
        elif prop_type == 'array':
            # Array without hints -> store as JSON
            column_def = f"{prop_name} JSON"
            if not is_required:
                column_def += " DEFAULT NULL"
            self._add_column(table_name, prop_name, column_def)
    
    def _resolve_ref(self, ref_path: str) -> Dict[str, Any]:
        """Resolve a $ref pointer."""
        if not ref_path.startswith('#/'):
            raise ValueError(f"Only local refs supported: {ref_path}")
        
        parts = ref_path[2:].split('/')
        current = self.schema
        
        for part in parts:
            current = current[part]
        
        return current
    
    def _map_type(self, json_type: str) -> str:
        """Map JSON Schema type to DuckDB type."""
        type_map = {
            'string': 'VARCHAR',
            'integer': 'INTEGER',
            'number': 'DOUBLE',
            'boolean': 'BOOLEAN'
        }
        return type_map.get(json_type, 'VARCHAR')


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <schema.json>")
        sys.exit(1)
    
    schema_path = Path(sys.argv[1])
    
    if not schema_path.exists():
        print(f"Error: Schema file not found: {schema_path}")
        sys.exit(1)
    
    with open(schema_path) as f:
        schema = json.load(f)
    
    generator = DuckDBDDLGenerator(schema)
    ddl = generator.generate()
    
    print(ddl)


if __name__ == '__main__':
    main()