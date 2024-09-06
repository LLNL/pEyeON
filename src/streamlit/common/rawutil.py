# wintappy.datautils.rawutil
import logging
import os
import re
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass
from glob import glob
from importlib.resources import files as resource_files
from typing import List, Optional

import duckdb
import pyarrow.parquet as pq
from duckdb import CatalogException
from pyarrow.lib import ArrowInvalid


@dataclass
class SqlStmt:
    name: str
    sql: str
    required: bool
    template: Optional[str]


class InvalidSchema(Exception):
    """
    Use to signal that the base schema doesn't match what we expect.
    """

    pass


def init_db(dataset=None, agg_level="rolling", database=":memory:", lookups=""):
    """
    Initialize an in memory db instance and configure with our custom sql.
    """
    con = duckdb.connect(database=database)
    # set caching dir to a temp directory location
    con.execute(f"SET temp_directory = '{tempfile.mkdtemp()}'")
    logging.debug(f"Duckdb info: {con.sql('CALL pragma_database_size()').fetchall()}")
    # TODO fix reference to SQL scripts
    run_sql_no_args(con, resource_files("wintappy.datautils").joinpath("initdb.sql"))
    if dataset is not None:
        globs = get_glob_paths_for_dataset(dataset, agg_level, lookups=lookups)
        create_views(con, globs)
    return con


def get_glob_paths_for_dataset(dataset, subdir="raw_sensor", include=None, lookups=""):
    """
    Build fully-qualifed glob paths for the dataset path.
    Return a map keyed by top level (event) dir.
    Expected structure is one of:

    Multiple files with/without Hive structure:
    {dataset}/{eventType}/[{attr=value}/..]/{filename}.parquet

    Single file at the top level:
    {dataset}/{eventType}.parquet
    """
    dataset_path = os.path.join(dataset, subdir)
    event_types = [
        os.path.join(dataset_path, fn)
        for fn in os.listdir(dataset_path)
        if include is None or fn.startswith(include)
    ]
    # optionally add lookup directory
    for path, _, files in os.walk(lookups):
        for name in files:
            if name.endswith(".parquet") or name.endswith(".csv"):
                event_types.append(os.path.join(path, name))
    globs = defaultdict(set)
    for cur_event in event_types:
        event_type = cur_event.split(os.sep)[-1]
        if os.path.isdir(cur_event):
            for dirpath, dirnames, filenames in os.walk(cur_event):
                if not dirnames:
                    if dirpath == cur_event:
                        # No dir globs needed
                        globs[event_type].add(f"{cur_event}{os.sep}*.parquet")
                    else:
                        # Remove the prefix, including event_type. Convert that to a glob.
                        subdir = dirpath.replace(cur_event, "")
                        glob = os.sep.join(["*"] * subdir.count(os.path.sep))
                        globs[event_type].add(os.path.join(cur_event, glob, "*.parquet"))
                        logging.debug(
                            f"{event_type} {subdir} {glob}"
                            f" has 0 subdirectories and {len(filenames)} files"
                        )
        else:
            # Treat as a simple, single file.
            if event_type.lower().endswith("parquet"):
                event = re.split(r"\.", event_type)[0]
                logging.info(f"Found {event} file: {event_type}")
                globs[event].add(cur_event)
            elif event_type.lower().endswith("csv"):
                event = re.split(r"\.", event_type)[0]
                logging.info(f"Found {event} file: {event_type}")
                globs[event].add(cur_event)
    return validate_globs(globs)


def validate_globs(raw_data):
    """
    raw_data is a map of event_type -> list of globs.
    Confirm that:
    * There is only 1 glob per event_type.
        A poorly formed dataset dir structure could result in multiples.
    * That there are actually files in the path.
        It's not uncommon for collection of specific feature type to by inconsistent over time.
    * For each file, confirm that it has data.
        Wintap does produce empty parquet files and that confuses duckdb and some other tools.
        * If an empty file is found, delete it
        * When complete, if all files were empty, then remove the event_type/glob entry.
    """
    globs = {}
    for event_type, pathspec_set in raw_data.items():
        # Normally, we'll only have one pathspec.
        if len(pathspec_set) > 1:
            raise Exception(f"Too many leaf dirs!: {pathspec_set}")
        else:
            pathspec = next(iter(pathspec_set))
            num_files = len(glob(pathspec))
            if num_files == 0:
                logging.info(f"Not found: {pathspec}  Skipping")
            else:
                logging.info(f"Found {num_files} parquet files in {pathspec}")
                #                for file in glob(pathspec):
                #                    table=pq.read_table(file)
                #                    if table.num_rows==0:
                #                        logging.info(f'{file} is empty, deleting.')
                #                        os.remove(file)
                #                        num_files-=1
                if num_files == 0:
                    logging.info(f"Skipping empty glob: {pathspec}")
                else:
                    globs[event_type] = pathspec
    return globs


def get_globs_for(dataset, daypk):
    """
    This function is intended to reduce the raw_sensor input
        to a single day of activity for processing.
    First, get the full glob paths for raw_sensor.  Then, splice in the dayPK specification.
    Finally, confirm that specific path exists and has files.
    """
    globs_all = get_glob_paths_for_dataset(dataset)
    globs = {}
    for event_type, pathspec in globs_all.items():
        # Add in the daypk filter
        pathspec = pathspec.replace(f"{os.sep}*{os.sep}", f"{os.sep}dayPK={daypk}{os.sep}", 1)
        num_files = len(glob(pathspec))
        if num_files == 0:
            logging.info(f"Not found: {pathspec}  Skipping")
        else:
            logging.info(f"Found {num_files} parquet files in {pathspec}")
            # Check for empty files. These confuse duckdb and lead to schema errors.
            for file in glob(pathspec):
                try:
                    table = pq.read_table(file)
                    if table.num_rows == 0:
                        logging.info(f"{file} is empty, deleting.")
                        os.remove(file)
                except ArrowInvalid:
                    # Move invalid files out of the way
                    # Move to dataset/invalid/path
                    logging.error(f"Invalid parquet: {file}")
                    os.rename(file, f"{file}.invalid")
                except OSError as e:
                    logging.error(f"OSError on {file}", e)
                    os.rename(file, f"{file}.oserror_invalid")
            # Sometimes, all the files have been removed, skip the pathspec in those cases
            if len(glob(pathspec)) > 0:
                globs[event_type] = pathspec
            else:
                logging.info(f"Skipping empty path: {pathspec}")
    return globs


def loadSqlStatements(file) -> List[SqlStmt]:
    """
    Read sql script. Parse into individual statements.

    Optional metadata can be set for each statement. Must be provided AFTER the first line of sql:
    --# name: [friendly name]
    --# required
    --# template: [path]

    Name - defaults to tablename for CREATE, all others default to the first line with line number.
    Best practice: for SELECT statements, provide a friendly name.

    Required - applies only to CREATEs.
        If present, and create fails, an empty table will be built using a parquet file
        located in ./schema/[template]/[name].parquet. Any data in the parquet will be ignored.

    Template - applies only to CREATEs.
        The subdirectory within "./schema" that has the template parquet file.
    """
    file = open(file, "r")
    lines = file.readlines()

    statements = []
    linenumber = 0
    inStmt = False
    for linenumber, line in enumerate(lines):
        keyword = line.split(" ")[0].strip().lower()
        if not inStmt and keyword in [
            "create",
            "alter",
            "update",
            "insert",
            "delete",
            "select",
        ]:
            # start of a new statement
            # For tables and views, use the object name
            if keyword == "create":
                name = line.strip().split()[-1]
            else:
                # Add line number to be sure its unique as there can be multiple of these per table
                name = f"{line.strip()}-{linenumber}"
            curStatement = SqlStmt(
                name=name,
                sql=line,
                required=False,
                template=None,
            )
            inStmt = True
        elif line.lower().startswith("--# name:"):
            # Override default name with provided one.
            curStatement.name = line.split(":")[1].strip()
        elif line.lower().startswith("--# required"):
            # This object is required to exist, so if execution fails,
            # an empty object will be created with a matching schema.
            curStatement.required = True
        elif line.lower().startswith("--# template:"):
            # Template identifies where the corresponding parquet template is
            # that will be used for creating empty objects.
            curStatement.template = line.split(":")[1].strip()
        else:
            if line.strip() == ";":
                # We done. Save the statement. Don't save the semi-colon.
                statements.append(curStatement)
                inStmt = False
                logging.debug(curStatement.sql)
            else:
                if inStmt:
                    curStatement.sql += line
    return statements


def generate_view_sql(event_map, start=None, end=None):
    """
    Create SQL for each of the event_types in the map.
    """
    # View Template
    stmts = []
    for event_type, pathspec in event_map.items():
        if "raw_" in event_type and "/raw_sensor/" in pathspec:
            # Raw files *may* have differing schemas, so enable union'ing of all schemas.
            # FIX in Wintap(?): Found that exact dups are in the raw tables,
            #     so remove them here using the GROUP BY ALL.
            # Only implement duplicate fix on 'raw_sensor' path.
            #     RAW tables in 'rolling' are already fixed.
            view_sql = get_raw_view(event_type, pathspec)
        elif pathspec.endswith(".csv"):
            view_sql = f"""
            create or replace view {event_type} as
            select * from read_csv('{pathspec}', AUTO_DETECT=TRUE)
            """
        else:
            view_sql = f"""
            create or replace view {event_type} as
            select * from parquet_scan('{pathspec}',hive_partitioning=1)
            """
            # Apply start/end filtering for rolling tables only.
            if "/rolling/" in pathspec:
                if start and end:
                    view_sql += f"where dayPK between {start} and {end}"
                if start is not None and end is None:
                    view_sql += f"where dayPK = {start}"
        if view_sql:
            stmts.append(view_sql)
            logging.debug(f"View for {event_type} using {pathspec}")
            logging.debug(view_sql)
    return stmts


def get_raw_view(event_type: str, pathspec):
    """
    The introduction of agentid causes a ripple effect thru all ETL SQL.
    For as long as is reasonable, auto-detect incoming parquet and add a null agentid when missing.
    This allows for processing of older data sets.
    At some point, a new, breaking schema change will happen
        and a different approach will be needed.
    """

    # Get the schema from the first parquet file
    schema = pq.read_schema(glob(pathspec)[0])
    if "agentid" in schema.names:
        view_sql = f"""
        create or replace view {event_type} as
        select *, count(*) num_dups
        from parquet_scan('{pathspec}',hive_partitioning=1,union_by_name=true) group by all
        """
    else:
        view_sql = f"""
        create or replace view {event_type} as
        select *, cast(null as varchar) agentid, count(*) num_dups
        from parquet_scan('{pathspec}',hive_partitioning=1,union_by_name=true) group by all
        """
    return view_sql


def create_views(con, event_map, start=None, end=None):
    stmts = generate_view_sql(event_map, start, end)
    for sql in stmts:
        cursor = con.cursor()
        try:
            cursor.execute(sql)
        except duckdb.duckdb.IOException as e:
            logging.error(f"SQL Failed: {sql}", e)
            logging.error("If the error is too many files open, try this on OSX:")
            logging.error("ulimit -Sn 524288; ulimit -Hn 10485760")
            raise e
        finally:
            cursor.close()


def validate_raw_views(con, raw_data, start=None, end=None):
    """
    Due to the variability in sensor configuration and collection issues,
    this hook is here to allow validating and possibly fixing, known problems:
    * In some cases, there are no raw_process_stop.parquet files
      which leads to all the unique fields defined in it to be missing,
      causing downstream SQL errors. Fixed here by copying in an empty parquet file.
    """

    if "raw_process" in raw_data.keys():
        # Validate existence of raw_process_stop fields. Shortcut by just checking for 1 for now.
        col_sql = """
            select table_catalog, table_name, column_name
            from information_schema.columns
            where table_name ilike 'raw_process'
            and lower(column_name)=lower('CPUCycleCount')
            """
        if con.sql(col_sql).count("*").fetchone()[0] == 0:
            # It's missing, create the empty file from the template
            src_file = resource_files("wintappy.schema.raw_sensor").joinpath(
                "raw_processstop.parquet"
            )
            # Destination will be the pathspec for raw_process, with a little tweaking:
            pathspec = raw_data["raw_process"]
            basepath = pathspec.split("*")[0]
            dest_file = os.path.join(
                basepath,
                "hourPK=00",
                f"EMPTY-raw_processstop-{int(time.time())}.parquet",
            )
            # Create the file by querying from template with the right schema
            logging.info(f"Creating empty raw_processstop.parquet in {pathspec}")
            con.execute(f"copy (select * from '{src_file}' where false) to '{dest_file}'")
            # Finally, recreate the raw_view.
            create_views(con, {"raw_process": pathspec}, start, end)


def create_raw_views(con, raw_data, start=None, end=None):
    """
    Create views in the db for each of the event_types.
    """
    create_views(con, raw_data, start, end)
    validate_raw_views(con, raw_data, start, end)


def create_empty_table(con, sqlstmt: SqlStmt):
    """
    Create an empty table from a parquet used as the template for the schema.
    This is useful when no data exists,
        but the structural element (table) is required for later SQL.

    template
    """
    fqfn = resource_files(f"wintappy.schema.{sqlstmt.template}").joinpath(f"{sqlstmt.name}.parquet")
    logging.debug(f"Creating empty table from: {fqfn}")
    sql = f"create table {sqlstmt.name} as select * from '{fqfn}' where False"
    try:
        con.execute(sql)
    except CatalogException as e:
        logging.warning(f"Warning! Failed to create empty table for {sqlstmt.name} due to:\n{e}")


def run_sql_no_args(con, sqlfile):
    """
    Execute all SQL statements in the file without binding any parameters.
    Format should be SQL statements (DDL) delimited with semi-colons. Comments are allowed SQL
    style:
       -- for single line
       /*
       Multi-line
       */
    """
    etl_sql = loadSqlStatements(sqlfile)
    for sqlstmt in etl_sql:
        logging.info(f"Processing: {sqlstmt.name}")
        try:
            con.execute(sqlstmt.sql)
        except CatalogException as e:
            logging.info(f"Missing dependent table/view for {sqlstmt.name}")
            logging.debug(f"Error: {e}\nSQL: {sqlstmt.sql}")
            if sqlstmt.required:
                logging.info(f"Creating empty object from {sqlstmt.template}")
                create_empty_table(con, sqlstmt)
        except duckdb.BinderException as e:
            logging.error(f"Likely missing column: \n{e}")
            raise InvalidSchema(f"Likely missing column: \n{e}")
        except Exception as e:
            logging.error(f"  Failed: {e}")
            raise


def get_db_objects(con, exclude=None):
    """
    Get all tables/views defined in the db.
    exclude should be a list of strings.
    If the strings appear in the object names, they'll be dropped from the result.
    """
    db_objects = con.execute(
        """select table_name, table_type
        from information_schema.tables
        where table_schema='main'
        order by all"""
    ).fetchall()
    if exclude is not None:
        # Find matches NOT including any of the words
        tables = [t for t, x in db_objects if not any(e in t for e in exclude)]
        logging.debug(f"Not Matches: {tables}")
    else:
        tables = [t for t, x in db_objects]
    return tables


def write_parquet(con, datasetpath, db_objects, daypk=None, agg_level="stdview"):
    """
    Write tables/views from duckdb instance to parquet.
    If daypk is provided, write to corresponding path in rolling.
    Otherwise, write to agg_level.
    """
    for object_name in db_objects:
        logging.info(f"Writing {object_name}")
        try:
            if daypk is None:
                pathspec = f"{datasetpath}{os.sep}{agg_level}"
                filename = f"{object_name}.parquet"
            else:
                pathspec = f"{datasetpath}{os.sep}rolling{os.sep}{object_name}{os.sep}dayPK={daypk}"
                filename = f"{object_name}-{daypk}.parquet"
            if not os.path.exists(pathspec):
                os.makedirs(pathspec)
                logging.debug(f"created folder: {pathspec} ")
            else:
                logging.debug(f"folder already exists: {pathspec}")
            # TODO Add test for file existence
            sql = f"COPY {object_name} TO '{pathspec}{os.sep}{filename}' (FORMAT 'parquet')"
            con.execute(sql)
        except duckdb.IOException as e:
            logging.exception(f"Failed to write: {object_name} as a result of {e}")
