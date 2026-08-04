from alive_progress import alive_bar, alive_it
from typing import Any, Optional

import datetime
import hashlib
import json
from importlib.metadata import version
from loguru import logger
from .observe import Observe
from .container import (
    binwalk_extract,
    cleanup_extraction,
    extract_container,
    should_use_binwalk,
    supported_container_types,
)
import os
import time
import threading # allows the monitor to run concurrently without blocking multiprocessing 
import multiprocessing
from sys import stderr
from uuid import uuid4


class Parse:
    """
    General parser for eyeon. Given a folder path, will return a list of observations.

    Parameters
    ----------

    dirpath : str
        A string specifying the folder to parse.
    """

    def __init__(self, dirpath: str, max_container_depth: int = 3) -> None:
        self.path = dirpath
        self.max_container_depth = max_container_depth

    @staticmethod
    def _create_hash(file: str, algorithm: str) -> str:
        hashers = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
        }
        with open(file, "rb") as f:
            h = hashers[algorithm]()
            h.update(f.read())
            return h.hexdigest()

    def _write_error_json(self, file: str, result_path: str, message: str, parent: Optional[str] = None) -> None:
        stat = os.stat(file)
        observation = {
            "uuid": str(uuid4()),
            "bytecount": stat.st_size,
            "filename": os.path.basename(file),
            "filetype": [],
            "metadata": {
                "error": {
                    "message": message,
                }
            },
            "magic": "",
            "modtime": datetime.datetime.fromtimestamp(
                stat.st_mtime, tz=datetime.timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S"),
            "observation_ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "permissions": oct(stat.st_mode),
            "md5": self._create_hash(file, "md5"),
            "sha1": self._create_hash(file, "sha1"),
            "sha256": self._create_hash(file, "sha256"),
            "signatures": [],
            "eyeon_version": version("peyeon"),
        }
        if parent:
            observation["parent"] = parent

        os.makedirs(result_path, exist_ok=True)
        outfile = self._error_json_output_path(result_path, observation)

        with open(outfile, "w") as f:
            json.dump(observation, f)

    @staticmethod
    def _error_json_output_path(result_path: str, observation: dict) -> str:
        base = os.path.join(result_path, f"{observation['filename']}.{observation['md5']}.json")
        if not os.path.exists(base):
            return base
        try:
            with open(base, "r") as f:
                existing_uuid = json.load(f).get("uuid")
        except (OSError, json.JSONDecodeError):
            existing_uuid = None
        if existing_uuid == observation["uuid"]:
            return base
        return os.path.join(result_path, f"{observation['filename']}.{observation['md5']}.{observation['uuid']}.json")

    def _observe(self, file_and_path: tuple) -> None:
        file, result_path, parent, depth = self._normalize_observe_args(file_and_path)
        try:
            o = Observe(file, parent=parent)
            extraction = None
            if depth < self.max_container_depth and supported_container_types(o.filetype):
                extraction = extract_container(file, o.filetype)
                container_md = o.metadata.setdefault("container_file", {})
                container_md.update(
                    {
                        "extracted": extraction["extracted"],
                        "extraction_status": extraction["extraction_status"],
                        "extracted_child_count": len(extraction["children"]),
                    }
                )
                if extraction["errors"]:
                    container_md["errors"] = extraction["errors"]
            elif depth < self.max_container_depth and should_use_binwalk(file, o.filetype):
                extraction = binwalk_extract(file)
                o.metadata["binwalk_file"] = extraction["metadata"]
            o.write_json(result_path)
            if extraction:
                try:
                    if extraction["extracted"]:
                        for child in extraction["children"]:
                            self._observe((child, result_path, o.uuid, depth + 1))
                finally:
                    cleanup_extraction(extraction["extract_dir"])
        except PermissionError:
            logger.warning(f"File {file} cannot be read.")
        except FileNotFoundError:
            logger.warning(f"No such file {file}.")
        except Exception as e:
            logger.exception(f"Observation failed for {file}: {e}")
            self._write_error_json(file, result_path, str(e), parent=parent)

    def _normalize_observe_args(self, file_and_path: tuple) -> tuple[str, str, Optional[str], int]:
        if len(file_and_path) == 2:
            file, result_path = file_and_path
            return file, result_path, None, 0
        if len(file_and_path) == 4:
            file, result_path, parent, depth = file_and_path
            return file, result_path, parent, depth
        raise ValueError(f"unexpected observe arguments: {file_and_path}")

    @staticmethod
    def _multiprocessing_context() -> multiprocessing.context.BaseContext:
        method = os.environ.get("EYEON_MULTIPROCESS_START_METHOD", "spawn")
        return multiprocessing.get_context(method)

    @staticmethod
    def _large_file_threshold() -> int:
        return int(os.environ.get("EYEON_SERIAL_LARGE_FILE_BYTES", str(50 * 1024 * 1024)))

    def _split_parallel_files(self, files: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
        threshold = self._large_file_threshold()
        if threshold <= 0:
            return files, []

        parallel_files = []
        serial_files = []
        for file_and_path in files:
            file, _ = file_and_path
            try:
                size = os.path.getsize(file)
            except OSError:
                parallel_files.append(file_and_path)
                continue
            if size >= threshold:
                serial_files.append(file_and_path)
            else:
                parallel_files.append(file_and_path)
        return parallel_files, serial_files

    def _observe_worker(self, args) -> None:
        """
        wrapper to handle and monitor observe workers. 
        Assists in identifying problematic files

        :param args: (file: str, result_path: str, progress_map: dict) 
        """

        file, result_path, progress_map = args

        logger.remove()
        logger.add(stderr, level=os.environ.get("LOGURU_LEVEL", "WARNING"))

        pid= os.getpid()
        start_time=time.time()

        progress_map[pid] = {
            "file": file,
            "start": start_time,
        }

        try:
            self._observe((file, result_path))
        finally:
            # Clear the entry when done or on error
            progress_map.pop(pid, None)


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
            parallel_files, serial_files = self._split_parallel_files(files)
            if serial_files:
                logger.warning(
                    "Processing {} files >= {} bytes serially to avoid multiprocessing hangs",
                    len(serial_files),
                    self._large_file_threshold(),
                )
            context = self._multiprocessing_context()
            manager=context.Manager()
            progress_map= manager.dict()

            def monitor():
                CHECK_INTERVAL=30 #seconds between checks
                HANG_THRESHOLD=120

                while True:
                    now = time.time()
                    workers=list(progress_map.items())
                    if not workers:
                        time.sleep(CHECK_INTERVAL)
                        continue
                        
                    for pid, info in workers:
                        file=info.get("file")
                        start=info.get("start", now)
                        duration=now-start
                        if duration > HANG_THRESHOLD:
                            logger.warning(
                                f"[monitor] - possible hung process: pid={pid} processing {file} for {duration:.1f}s"
                            )
                    
                    time.sleep(CHECK_INTERVAL) #sleep so it's not infinitely spinning

            monitor_thread = threading.Thread(target=monitor, daemon=True) #run monitor thread in the background, removes when finished
            monitor_thread.start()


            with alive_bar(
                len(files),
                spinner="waves",
                title=f"Parsing with {threads} threads..."
            ) as bar:
                if parallel_files:
                    with context.Pool(threads, maxtasksperchild=1) as p:
                        # each worker gets the file, result_path, and the shared progress_map
                        iterable = [
                            (file, result_path, progress_map) for (file, result_path) in parallel_files
                        ]
                        for _ in p.imap_unordered(self._observe_worker, iterable):
                            bar()  # update the bar when a thread finishes
                for filet in serial_files:
                    self._observe(filet)
                    bar()

        else:
            #Single process path (no inter‑process monitoring needed)
            for filet in alive_it(files, spinner="waves", title="Parsing files..."):
                self._observe(filet)
