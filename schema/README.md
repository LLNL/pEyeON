# Winning strategy: datamodel-codegen

* Generates a pydantic class

  ```bash
  datamodel-codegen \
  --input observation.schema.json \
  --input-file-type jsonschema \
  --target-python-version 3.11 \
  --output observation_models.py \
  --class-name ObservationModel \
  --use-standard-collections \
  --output-model-type pydantic_v2.BaseModel
  ```

* Just use that class
  * Implements "required" fields from the Schema
  * Datatypes
* Supports autocomplete since its just a static class
* Implement a Makefile to keep dataclass current when schema changes?

## Example Usage

```python
from observation_models import ObservationModel
eyeon = ObservationModel(bytecount=5, filename='test.me', magic='ooh/magic', md5='sumhash', observation_ts='10/13/2025', sha1='shame', sha256='sha256', uuid='xyz')
```

# Details 

## datamodel-codegen command overview

This command uses datamodel-code-generator to convert a JSON Schema file into Python classes targeting Pydantic v2, with specific output and type behavior.

Official documentation:
- https://koxudaxi.github.io/datamodel-code-generator/

### What the command does
- Reads your JSON Schema file, observation.schema.json.
- Generates Python model classes that conform to the schema.
- Targets Python 3.13 syntax and standard library types.
- Emits Pydantic v2 BaseModel classes for validation and serialization.
- Uses a specific top-level class name for the root schema.

### Command, broken down by argument

- `datamodel-codegen`
  - The CLI tool that generates Python models from various schema sources.

- `--input observation.schema.json`
  - Path to the source schema file.
  - Tells the generator what to parse.

- `--input-file-type jsonschema`
  - Explicitly sets the input format, helpful when the file extension is ambiguous.
  - Ensures the parser interprets the file as JSON Schema, not OpenAPI or others.

- `--target-python-version 3.11`
  - Controls the Python syntax features in the generated code.
  - For Python 3.11, you get modern typing and dataclass, typing behaviors appropriate for that version.

- `--output observation_models.py`
  - Destination file for the generated models.
  - All classes are written into this single module.

- `--class-name ObservationModel`
  - Sets the name of the root model class that represents the schema’s top-level object.
  - Useful for autocompletion and clear imports in your app code.

- `--use-standard-collections`
  - Uses built-in collection types like list and dict instead of typing.List and typing.Dict in annotations where appropriate.
  - Generally results in cleaner, more modern type hints.

- `--output-model-type pydantic_v2.BaseModel`
  - Targets Pydantic v2’s BaseModel for the generated classes.
  - Ensures compatibility with Pydantic v2 APIs, including model_dump, model_validate, and RootModel for root schemas where needed.
