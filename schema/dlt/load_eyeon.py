import dlt
import json
from pathlib import Path

depth=2
source = "./"

@dlt.source(name="eyeon_metadata")
def eyeon_source():
    # Resource for the main files table
    @dlt.resource(
        table_name="files",
        write_disposition="merge",
#        primary_key="uuid",
        max_table_nesting=depth
    )
    def files_resource():
        for path in Path(source).glob("*.json"):
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                    metadata = data.pop("metadata", None)
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
                    for md_type, md_data in data.get("metadata", {}).items():
                        record = {
                            "uuid": data["uuid"],  # FK back to files.uuid
                            **md_data  # unpack type-specific fields
                        }
                        record["_metadata_table_name"] = f"metadata_{md_type.lower()}"
                        if md_type != 'java_file':
                            yield record
                        else:
                            # For javaClasses, convert the dict key class name to a field
                            # If there are no classes, just remove the empty definition
                            if 'javaClasses' in md_data and isinstance(md_data['javaClasses'], dict):
                                # Convert the dict with class name keys into a list
                                # Pop the javaClasses list. This also removes it from md_data.
                                classes = md_data.pop('javaClasses')
                                class_list = []
                                for classname, class_data in classes.items():
                                    class_data['classname'] = classname  # Add classname as a field
                                    class_list.append(class_data)
                                
                                md_data['javaClasses'] = class_list
                                md_data["_metadata_table_name"] = f"metadata_{md_type.lower()}"
                                yield md_data
                        
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

# Run the pipeline
pipeline = dlt.pipeline(
    pipeline_name="eyeon_metadata",
    destination="duckdb",  # or duckdb, bigquery, etc.
    dataset_name="raw",
    dev_mode=True
)

pipeline.run(eyeon_source())