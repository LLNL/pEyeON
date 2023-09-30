import logging
from typing import Any
from .setup_log import logger  # noqa: F401
from .observe import Observe
import os

log = logging.getLogger("eyeon.parse")


class Parse:
    """
    General parser for eyeon. Given a folder path, will return a list of observations.
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
        o = Observe(file)
        o.write_json(result_path)

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
