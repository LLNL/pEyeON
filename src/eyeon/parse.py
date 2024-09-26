import logging
from alive_progress import alive_bar, alive_it
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
        with alive_bar(
            bar=None,
            elapsed_end=False,
            monitor_end=False,
            stats_end=False,
            receipt_text=True,
            spinner="waves",
            stats=False,
            monitor=False,
        ) as bar:
            bar.title("Collecting Files... ")
            files = [
                (os.path.join(dir, file), result_path)
                for dir, _, files in os.walk(self.path)
                for file in files
            ]
            bar.title("")
            bar.text(f"{len(files)} files collected")

        if threads > 1:
            from multiprocessing import Pool

            with Pool(threads) as p:
                with alive_bar(
                    len(files), spinner="waves", title=f"Parsing with {threads} threads..."
                ) as bar:
                    for _ in p.imap_unordered(self._observe, files):
                        bar()  # update the bar when a thread finishes

        else:
            for filet in alive_it(files, spinner="waves", title="Parsing files..."):
                self._observe(filet)

    def write_database(self, database: str, outdir: str = "./results") -> None:
        """
        Parse all output json files and add to database

        Parameters
        ----------
            database : str
                The filepath to the duckdb database
            outdir : str
                A string specifying where results were saved
        """
        if os.path.exists(outdir) and database:
            try:
                with alive_bar(
                    bar=None,
                    elapsed_end=False,
                    monitor_end=False,
                    stats_end=False,
                    receipt_text=True,
                    spinner="waves",
                    stats=False,
                    monitor=False,
                ) as bar:
                    bar.title(f"Writing to database {database}")
                    db_exists = os.path.exists(database)
                    db_path = os.path.dirname(database)
                    if db_path:
                        os.makedirs(db_path, exist_ok=True)
                    con = duckdb.connect(database)  # creates or connects
                    if not db_exists:  # database exists, load the json file in
                        # create table and views from sql
                        con.sql(files("database").joinpath("eyeon-ddl.sql").read_text())

                    # add the file to the observations table, making it match template
                    # observations with missing keys keys with null
                    con.sql(
                        f"""
                    insert into observations by name
                    select * from
                    read_json_auto(['{outdir}/*.json',
                                    '{files('database').joinpath('observations.json')}'],
                                    union_by_name=true, auto_detect=true)
                    where filename is not null;
                    """
                    )
                    bar.title("")
                    bar.text("Database updated")
                    con.close()
            except duckdb.IOException as ioe:
                con = None
                s = f":exclamation: Failed to attach to db {database}: {ioe}"
                print(s)
        else:
            raise FileNotFoundError
