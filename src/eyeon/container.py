import bz2
import gzip
import json
import lzma
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any


CONTAINER_FILETYPES = {
    "ZIP",
    "TAR",
    "GZIP",
    "BZIP2",
    "XZ",
    "RAR",
    "ISO_9660_CD",
    "DOCKER_TAR",
    "DOCKER_GZIP",
}
BINWALK_DEFAULT_EXTENSIONS = {".bin", ".chk", ".firmware", ".fw", ".img", ".trx"}


def supported_container_types(filetypes: list[str] | None) -> list[str]:
    if not filetypes:
        return []
    return [filetype for filetype in filetypes if filetype in CONTAINER_FILETYPES]


def should_use_binwalk(file_path: str, filetypes: list[str] | None) -> bool:
    configured = os.environ.get("EYEON_BINWALK", "").lower()
    if configured in {"0", "false", "no", "off"}:
        return False
    if configured in {"1", "true", "yes", "on"}:
        return True
    if filetypes and "UIMAGE" in filetypes:
        return True
    return Path(file_path).suffix.lower() in BINWALK_DEFAULT_EXTENSIONS


def binwalk_extract(file_path: str) -> dict[str, Any]:
    extract_dir = tempfile.mkdtemp(prefix="eyeon-binwalk-")
    command = _binwalk_command()
    if command is None:
        return {
            "extracted": False,
            "metadata": {
                "available": False,
                "scanned": False,
                "extracted": False,
                "extraction_status": "unavailable",
                "findings": [],
                "extractions": [],
                "errors": ["binwalk executable not found"],
            },
            "extract_dir": extract_dir,
            "children": [],
        }

    json_path = Path(extract_dir) / "binwalk.json"
    binwalk_out = Path(extract_dir) / "output"
    binwalk_out.mkdir()
    args = [command, "-q", "-e", "-C", str(binwalk_out), "-l", str(json_path), file_path]
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return {
            "extracted": False,
            "metadata": {
                "available": False,
                "scanned": False,
                "extracted": False,
                "extraction_status": "unavailable",
                "command": args,
                "findings": [],
                "extractions": [],
                "errors": [f"binwalk executable not found: {command}"],
            },
            "extract_dir": extract_dir,
            "children": [],
            "errors": [f"binwalk executable not found: {command}"],
        }
    raw_json = _load_binwalk_json(json_path)
    findings = _binwalk_findings(raw_json)
    extractions = _binwalk_extractions(raw_json)
    children = _binwalk_children(binwalk_out, file_path)
    extraction_failures = [item for item in extractions if not item.get("success")]
    errors = []
    if result.stderr:
        errors.append(result.stderr.strip())
    if result.returncode != 0:
        errors.append(f"binwalk exited with status {result.returncode}")
    status = "success"
    if extraction_failures:
        status = "partial"
    if result.returncode != 0 or (not children and findings):
        status = "failed"
    if not findings:
        status = "no_findings"
    return {
        "extracted": bool(children),
        "metadata": {
            "available": True,
            "scanned": True,
            "extracted": bool(children),
            "extraction_status": status,
            "command": args,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "findings": findings,
            "extractions": extractions,
            "extraction_failures": extraction_failures,
            "errors": errors,
        },
        "extract_dir": extract_dir,
        "children": children,
        "errors": errors,
    }


def container_metadata(file_path: str, filetypes: list[str] | None) -> dict[str, Any] | None:
    formats = supported_container_types(filetypes)
    if not formats:
        return None

    metadata: dict[str, Any] = {
        "formats": formats,
        "extractable": True,
        "extracted": False,
        "extraction_status": "not_attempted",
        "child_count": 0,
        "members": [],
    }
    try:
        metadata["members"] = list_members(file_path, formats[0])
        metadata["child_count"] = len(metadata["members"])
    except Exception as exc:
        metadata["extractable"] = False
        metadata["extraction_status"] = "metadata_error"
        metadata["errors"] = [str(exc)]
    return metadata


def list_members(file_path: str, container_type: str) -> list[dict[str, Any]]:
    if container_type == "ZIP":
        with zipfile.ZipFile(file_path) as archive:
            return [
                {
                    "path": item.filename,
                    "size": item.file_size,
                    "compressed_size": item.compress_size,
                    "is_dir": item.is_dir(),
                }
                for item in archive.infolist()
            ]
    if container_type in {"TAR", "DOCKER_TAR"}:
        with tarfile.open(file_path) as archive:
            return [_tar_member_metadata(item) for item in archive.getmembers()]
    if container_type == "DOCKER_GZIP":
        with tarfile.open(file_path, "r:gz") as archive:
            return [_tar_member_metadata(item) for item in archive.getmembers()]
    if container_type in {"GZIP", "BZIP2", "XZ"}:
        try:
            with tarfile.open(file_path, _tar_mode(container_type)) as archive:
                return [_tar_member_metadata(item) for item in archive.getmembers()]
        except tarfile.ReadError:
            pass
        return [
            {
                "path": decompressed_filename(file_path, container_type),
                "size": None,
                "is_dir": False,
            }
        ]
    if container_type == "RAR":
        return _list_rar_members(file_path)
    if container_type == "ISO_9660_CD":
        return _list_external_members(file_path)
    return []


def extract_container(file_path: str, filetypes: list[str] | None) -> dict[str, Any]:
    formats = supported_container_types(filetypes)
    if not formats:
        return {
            "extracted": False,
            "extraction_status": "unsupported",
            "extract_dir": None,
            "children": [],
            "errors": [],
        }

    extract_dir = tempfile.mkdtemp(prefix="eyeon-container-")
    try:
        children = _extract_to(file_path, formats[0], extract_dir)
        return {
            "extracted": True,
            "extraction_status": "success",
            "extract_dir": extract_dir,
            "children": children,
            "errors": [],
        }
    except Exception as exc:
        return {
            "extracted": False,
            "extraction_status": "failed",
            "extract_dir": extract_dir,
            "children": [],
            "errors": [str(exc)],
        }


def cleanup_extraction(extract_dir: str | None) -> None:
    if extract_dir and os.path.exists(extract_dir):
        shutil.rmtree(extract_dir)


def _binwalk_command() -> str | None:
    configured = os.environ.get("EYEON_BINWALK_PATH")
    if configured:
        return configured
    return shutil.which("binwalk")


def _load_binwalk_json(json_path: Path) -> Any:
    try:
        with json_path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _binwalk_analysis(raw_json: Any) -> dict[str, Any]:
    if isinstance(raw_json, list) and raw_json and isinstance(raw_json[0], dict):
        analysis = raw_json[0].get("Analysis")
        if isinstance(analysis, dict):
            return analysis
    return {}


def _binwalk_findings(raw_json: Any) -> list[dict[str, Any]]:
    findings = []
    for item in _binwalk_analysis(raw_json).get("file_map", []):
        findings.append(
            {
                "id": item.get("id"),
                "offset": item.get("offset"),
                "name": item.get("name"),
                "description": item.get("description"),
                "size": item.get("size"),
                "confidence": item.get("confidence"),
                "extraction_declined": item.get("extraction_declined"),
            }
        )
    return findings


def _binwalk_extractions(raw_json: Any) -> list[dict[str, Any]]:
    extractions = []
    for finding_id, item in _binwalk_analysis(raw_json).get("extractions", {}).items():
        extractions.append(
            {
                "finding_id": finding_id,
                "success": item.get("success", False),
                "extractor": item.get("extractor"),
                "output_directory": item.get("output_directory"),
                "size": item.get("size"),
                "do_not_recurse": item.get("do_not_recurse"),
            }
        )
    return extractions


def _binwalk_children(output_dir: Path, file_path: str) -> list[str]:
    original = Path(file_path).name
    children = []
    for path in output_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.parent == output_dir and path.name == original:
            continue
        children.append(str(path))
    return sorted(children)


def decompressed_filename(file_path: str, container_type: str) -> str:
    path = Path(file_path)
    suffixes = {
        "GZIP": ".gz",
        "BZIP2": ".bz2",
        "XZ": ".xz",
    }
    suffix = suffixes[container_type]
    if path.name.endswith(suffix):
        return path.name[: -len(suffix)] or f"{path.name}.decompressed"
    return f"{path.name}.decompressed"


def _extract_to(file_path: str, container_type: str, extract_dir: str) -> list[str]:
    if container_type == "ZIP":
        with zipfile.ZipFile(file_path) as archive:
            _safe_extract_zip(archive, extract_dir)
    elif container_type in {"TAR", "DOCKER_TAR"}:
        with tarfile.open(file_path) as archive:
            _safe_extract_tar(archive, extract_dir)
    elif container_type == "DOCKER_GZIP":
        with tarfile.open(file_path, "r:gz") as archive:
            _safe_extract_tar(archive, extract_dir)
    elif container_type in {"GZIP", "BZIP2", "XZ"}:
        try:
            with tarfile.open(file_path, _tar_mode(container_type)) as archive:
                _safe_extract_tar(archive, extract_dir)
        except tarfile.ReadError:
            _decompress_single_file(file_path, container_type, extract_dir)
    elif container_type == "RAR":
        _extract_rar(file_path, extract_dir)
    elif container_type == "ISO_9660_CD":
        _extract_external(file_path, extract_dir)
    else:
        raise ValueError(f"unsupported container type: {container_type}")
    return _extracted_files(extract_dir)


def _safe_extract_zip(archive: zipfile.ZipFile, extract_dir: str) -> None:
    for item in archive.infolist():
        _validate_extract_path(extract_dir, item.filename)
    archive.extractall(extract_dir)


def _safe_extract_tar(archive: tarfile.TarFile, extract_dir: str) -> None:
    for item in archive.getmembers():
        _validate_extract_path(extract_dir, item.name)
        if item.issym() or item.islnk():
            raise ValueError(f"refusing to extract tar link: {item.name}")
    archive.extractall(extract_dir)


def _validate_extract_path(extract_dir: str, member_name: str) -> None:
    root = Path(extract_dir).resolve()
    target = (root / member_name).resolve()
    if root != target and root not in target.parents:
        raise ValueError(f"refusing to extract outside target directory: {member_name}")


def _decompress_single_file(file_path: str, container_type: str, extract_dir: str) -> None:
    modules = {
        "GZIP": gzip,
        "BZIP2": bz2,
        "XZ": lzma,
    }
    output_path = Path(extract_dir) / decompressed_filename(file_path, container_type)
    with modules[container_type].open(file_path, "rb") as source:
        with output_path.open("wb") as target:
            shutil.copyfileobj(source, target)


def _tar_mode(container_type: str) -> str:
    return {
        "GZIP": "r:gz",
        "BZIP2": "r:bz2",
        "XZ": "r:xz",
    }[container_type]


def _list_rar_members(file_path: str) -> list[dict[str, Any]]:
    import rarfile

    with rarfile.RarFile(file_path) as archive:
        return [
            {
                "path": item.filename,
                "size": item.file_size,
                "compressed_size": item.compress_size,
                "is_dir": item.isdir(),
            }
            for item in archive.infolist()
        ]


def _extract_rar(file_path: str, extract_dir: str) -> None:
    import rarfile

    with rarfile.RarFile(file_path) as archive:
        for item in archive.infolist():
            _validate_extract_path(extract_dir, item.filename)
        archive.extractall(extract_dir)


def _seven_zip_command() -> str:
    configured = os.environ.get("EYEON_7Z_PATH")
    if configured:
        return configured
    for command in ("7zz", "7z"):
        path = shutil.which(command)
        if path:
            return path
    raise FileNotFoundError("7zz or 7z is required to inspect/extract ISO_9660_CD")


def _list_external_members(file_path: str) -> list[dict[str, Any]]:
    result = subprocess.run(
        [_seven_zip_command(), "l", "-slt", file_path],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError(result.stderr.strip() or f"7z list failed with status {result.returncode}")
    members = []
    current: dict[str, Any] = {}
    for line in result.stdout.splitlines():
        if not line:
            if current.get("Path"):
                members.append(_seven_zip_member_metadata(current))
            current = {}
            continue
        if " = " in line:
            key, value = line.split(" = ", 1)
            current[key] = value
    if current.get("Path"):
        members.append(_seven_zip_member_metadata(current))
    return [member for member in members if member["path"] != file_path]


def _seven_zip_member_metadata(member: dict[str, Any]) -> dict[str, Any]:
    attributes = member.get("Attributes", "")
    return {
        "path": member["Path"],
        "size": int(member["Size"]) if member.get("Size", "").isdigit() else None,
        "is_dir": "D" in attributes,
    }


def _extract_external(file_path: str, extract_dir: str) -> None:
    command = _seven_zip_command()
    result = subprocess.run(
        [command, "x", f"-o{extract_dir}", "-y", file_path],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError(result.stderr.strip() or f"7z extract failed with status {result.returncode}")


def _extracted_files(extract_dir: str) -> list[str]:
    root = Path(extract_dir)
    return sorted(str(path) for path in root.rglob("*") if path.is_file())


def _tar_member_metadata(item: tarfile.TarInfo) -> dict[str, Any]:
    return {
        "path": item.name,
        "size": item.size,
        "is_dir": item.isdir(),
        "is_link": item.issym() or item.islnk(),
    }
