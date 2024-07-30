import logging
from typing import Any

# from .setup_log import logger  # noqa: F401
from .observe import Observe
import os
import duckdb
from importlib.resources import files

log = logging.getLogger("eyeon.parse")


class Parse:
    """
    General parser for eyeon. Given a folder path, will return a list of observations.

    Parameters
    ----------

    dirpath : str
        A string specifying the folder to parse.

    log_level : int, optional (default=logging.ERROR)
        As logging level; defaults to ERROR.

    log_file : str, optional (default=None)
        A file to write logs. If None, will print log to console.
    """

    def __init__(self, dirpath: str, log_level: int = logging.ERROR, log_file: str = None) -> None:
        if log_file:
            fh = logging.FileHandler(log_file)
            fh.setFormatter(
                logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            )
            logging.getLogger().handlers.clear()  # remove console log
            log.addHandler(fh)
        logging.getLogger().setLevel(log_level)
        self.path = dirpath

    def _observe(self, file_and_path: tuple) -> None:
        file, result_path = file_and_path
        try:
            o = Observe(file)
            o.write_json(result_path)
        except PermissionError:
            log.warning(f"File {file} cannot be read.")
        except FileNotFoundError:
            log.warning(f"No such file {file}.")

    def __call__(self, result_path: str = "./results", threads: int = 1) -> Any:
        files = [
            (os.path.join(dir, file), result_path)
            for dir, _, files in os.walk(self.path)
            for file in files
        ]

        if threads > 1:
            from multiprocessing import Pool

            with Pool(threads) as p:
                p.map(self._observe, files)

        else:
            for filet in files:
                self._observe(filet)

    def write_database(self, database: str, outdir: str = "./results"):
        """
        Parse all output json files and add to database

        Parameters
        ----------
            database : str
                The filepath to the duckdb database
            outdir : str
                A string specifying where results were saved
        """
        if os.path.exists(outdir):
            try:
                print(f"Writing to database {database}")
                db_exists = os.path.exists(database)
                con = duckdb.connect(database)  # creates or connects
                if db_exists:  # database exists, load the json file in
                    con.sql(f"copy raw_pf from read_json('{outdir}/*.json', union_by_name=true);")
                else:  # No database, instantiate
                    con = duckdb.connect(database)
                    # initialize following the schema
                    con.sql(f"create table raw_pf as select * from read_json('{outdir}/*.json', union_by_name=true);")
                    # create all of the views using eyeon-ddl.sql
                    con.sql(files('database').joinpath('eyeon-ddl.sql').read_text())
                con.close()
            except duckdb.IOException as ioe:
                con = None
                return f":exclamation: Failed to attach to db {database}: {ioe}"
        else:
            raise FileNotFoundError
