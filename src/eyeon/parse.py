import logging
from tqdm import tqdm as progress_bar
from typing import Any

# from .setup_log import logger  # noqa: F401
from .observe import Observe
import os

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
                progress_bar(p.imap(self._observe, files))  # imap returns an iterator

        else:
            for filet in progress_bar(files):
                self._observe(filet)
