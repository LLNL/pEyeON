import argparse
import dlt
import json
import logging
from pathlib import Path

@dlt.source(name="dlt_schema")
def dlt_schema(source, depth):
    # Resource for the schema json
    @dlt.resource(
        table_name="dlt_schema",
        write_disposition="merge",
#        primary_key="uuid",
        max_table_nesting=depth
    )
    def files_resource():
        for path in Path(source).glob("*.json"):
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                    tables = data.pop("tables", None)
                yield data
            except Exception as e:
                # Yield error record instead of failing
                yield {
                        '_source_file': str(path),
                        '_error': str(e),
                        '_parse_failed': True,
                        '_code_source': 'file_resource',
                        '_metadata_table_name': "json_errors"
                    }
            
    # Resource for metadata: dispatches to per-type tables dynamically
    @dlt.resource(
        table_name=lambda item: item["_metadata_table_name"],
        write_disposition="append",  # or "merge" if you add a PK for metadata
        max_table_nesting=depth
    )
    def metadata_resource():
        for path in Path(source).glob("*.json"):
            print(path)
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                    for md_type, md_data in data.get("tables", {}).items():
                        for k,v in md_data.get("columns").items():
                            record = {
                                "column_name" : v.get('name'),
                                "data_type": v.get('data_type'),
                                "nullable": v.get('nullable')
                            }
                            record["_metadata_table_name"] = f"metadata_{md_type.lower()}"
                            yield record
                        
            except Exception as e:
                # Yield error record instead of failing
                yield {
                        '_source_file': str(path),
                        '_error': str(e),
                        '_parse_failed': True,
                        '_code_source': 'metadata_resource',
                        '_metadata_table_name': "json_errors"
                    }


    return files_resource(), metadata_resource()

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
        pipeline_name="dlt_schemas",
        destination="duckdb",  # or duckdb, bigquery, etc.
        dataset_name="raw",
        dev_mode=True
    )
    pipeline.run(dlt_schema(args.source, args.depth))

    # Snapshot the schema for change tracking

if __name__ == "__main__":
    main()

