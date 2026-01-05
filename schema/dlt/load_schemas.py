import argparse
import dlt
import json
import logging
from pathlib import Path
from dlt.sources.filesystem import filesystem

@dlt.source(name="dlt_schema_files")
def dlt_schema(source, depth):
    # CREATE FILESYSTEM SOURCE
    fs = filesystem(
        bucket_url=f"file://{Path(source).absolute()}",
        file_glob="*.json"
    )

    @dlt.resource(
        table_name="grantj_schema",
        write_disposition="merge",
        max_table_nesting=depth
    )
    def schema_resource():
        # ITERATE OVER FILESYSTEM SOURCE INSTEAD OF Path.glob()
        for file_item in fs:
            path = file_item['file_url'].replace('file://', '')  # Get actual path
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                    data.pop('tables')
                    data["_dlt_file"] = file_item['file_url'],  # ADD FILE TRACKING
                    data["_dlt_modified"] = file_item['modification_date']  # ADD TIMESTAMP
                    yield data
            except Exception as e:
                # Yield error record instead of failing
                yield {
                    '_source_file': file_item['file_url'],
                    '_error': str(e),
                    '_parse_failed': True,
                    '_code_source': 'file_resource',
                    '_metadata_table_name': "json_errors"
                }

    
    @dlt.resource(
        table_name="grantj_table",
        write_disposition="merge",
        max_table_nesting=depth
    )
    def table_resource():
        # ITERATE OVER FILESYSTEM SOURCE INSTEAD OF Path.glob()
        for file_item in fs:
            path = file_item['file_url'].replace('file://', '')  # Get actual path
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                tables = data.pop("tables", None)
                for k,v in tables.items():
                    # I want to rename just the name column, so pop it off and do it separately
                    name = v.pop('name')
                    v.pop('columns')
                    record = {
                        "table_name": name,
                        # Add all the table level fields
                        **v,
#                        # Add all the schema level fields
#                        **data,
                        "_dlt_file": file_item['file_url'],  # ADD FILE TRACKING
                        "_dlt_modified": file_item['modification_date']  # ADD TIMESTAMP
                    }
                    yield record
            except Exception as e:
                # Yield error record instead of failing
                yield {
                    '_source_file': file_item['file_url'],
                    '_error': str(e),
                    '_parse_failed': True,
                    '_code_source': 'file_resource',
                    '_metadata_table_name': "json_errors"
                }
    
    @dlt.resource(
        table_name="grantj_column",
        write_disposition="append",
        max_table_nesting=depth
    )
    def column_resource():
        for file_item in fs:
            path = file_item['file_url'].replace('file://', '')
            print(path)
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                for md_type, md_data in data.get("tables", {}).items():
                    for k,v in md_data.get("columns").items():
                        record = {
                            "column_name" : v.get('name'),
                            "data_type": v.get('data_type'),
                            "nullable": v.get('nullable'),
                            "_dlt_file": file_item['file_url'],  # ADD FILE TRACKING
                            "_dlt_modified": file_item['modification_date']  # ADD TIMESTAMP
                        }
                        record["table_name"] = f"{md_type.lower()}"
                        yield record
            except Exception as e:
                yield {
                    '_source_file': file_item['file_url'],
                    '_error': str(e),
                    '_parse_failed': True,
                    '_code_source': 'metadata_resource',
                    '_metadata_table_name': "json_errors"
                }
    
    # APPLY INCREMENTAL HINTS
    schema_resource.apply_hints(
        incremental=dlt.sources.incremental("_dlt_modified")
    )
    table_resource.apply_hints(
        incremental=dlt.sources.incremental("_dlt_modified")
    )
    column_resource.apply_hints(
        incremental=dlt.sources.incremental("_dlt_modified")
    )
    
    return schema_resource(), table_resource(), column_resource()

def main(argv=None) -> None:
    logging.basicConfig(
    level=logging.INFO,                  # Change to DEBUG if you need more verbosity
    format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    )

    parser = argparse.ArgumentParser(
        prog="load_eyeon.py", description="Load EyeOn JSON into base tables."
    )
    parser.add_argument('--source', required=True, help='Source path of JSON files')
    parser.add_argument('--depth', required=False, default=4, help='Depth that DLT will attempt to parse for complex types')

    args = parser.parse_args()

    # Define and run the pipeline
    pipeline = dlt.pipeline(
        pipeline_name="grantj_schemas",
        destination="duckdb",  # or duckdb, bigquery, etc.
        dataset_name="raw",
        dev_mode=True
    )
    pipeline.run(dlt_schema(args.source, args.depth))

    # Snapshot the schema for change tracking

if __name__ == "__main__":
    main()
