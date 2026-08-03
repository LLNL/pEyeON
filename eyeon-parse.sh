#!/usr/bin/env bash
set -euo pipefail

# eyeon-parse: wrapper for "eyeon parse -o O -t N SOURCE" inside the container.
#
# All inputs can be provided by environment variables and/or command line args.
# Command line args take precedence over environment variables.
#
# Usage:
#   eyeon-parse [--util-cd UTIL_CD] [--dir SOURCE] [--threads THREADS] \
#               [--image IMAGE] [--dataset-path DATASET_PATH] [--runtime RUNTIME]
#   eyeon-parse UTIL_CD SOURCE [DATASET_PATH] [THREADS]
#
# Environment variables (optional):
#   EYEON_UTIL_CD
#   EYEON_SOURCE
#   EYEON_THREADS      (default: 8)
#   EYEON_IMAGE        (default: ghcr.io/llnl/peyeon:latest; override for dev/test images)
#   EYEON_DATASET_PATH (default: datasets.dataset_path from EyeOnData.toml)
#   EYEON_LOG_LEVEL    (default: WARNING)
#   EYEON_MODE         auto|container|vm (default: auto)
#   EYEON_OWNER        (required when running as root unless passthrough is enabled)
#   EYEON_UID / EYEON_GID
#   EYEON_PASSTHROUGH_ROOT=1 (intentionally create root-owned outputs)
#   EYEON_CONTAINER_RUNTIME=docker|podman
#   DEBUG=1            (print docker/env details and launch an interactive debug shell)
#
# Example dev image override:
#   EYEON_IMAGE=ghcr.io/llnl/peyeon:dev-<sha> ./eyeon-parse.sh UTIL_CD SOURCE

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETTINGS_FILE=""

resolve_settings_file() {
  local candidates=()

  if [[ -n "${EYEON_EYEONDATA_TOML:-}" ]]; then
    candidates+=("$EYEON_EYEONDATA_TOML")
  fi

  candidates+=("$PWD/EyeOnData.toml")
  candidates+=("$SCRIPT_DIR/EyeOnData.toml")
  candidates+=("$SCRIPT_DIR/../pEyeON-Analytics/EyeOnData.toml")
  candidates+=("/opt/pEyeON-Analytics/EyeOnData.toml")
  candidates+=("$HOME/pEyeON-Analytics/EyeOnData.toml")

  local candidate
  for candidate in "${candidates[@]}"; do
    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

read_dataset_path_from_toml() {
  if [[ -z "$SETTINGS_FILE" || ! -f "$SETTINGS_FILE" ]]; then
    return 0
  fi

  awk '
    BEGIN { in_datasets = 0 }
    /^[[:space:]]*\[/ {
      in_datasets = ($0 ~ /^[[:space:]]*\[datasets\][[:space:]]*$/)
      next
    }
    in_datasets && /^[[:space:]]*dataset_path[[:space:]]*=/ {
      value = $0
      sub(/^[[:space:]]*dataset_path[[:space:]]*=[[:space:]]*/, "", value)
      sub(/[[:space:]]*(#.*)?$/, "", value)
      sub(/^"/, "", value)
      sub(/"$/, "", value)
      print value
      exit
    }
  ' "$SETTINGS_FILE"
}

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") [--util-cd UTIL_CD] [--dir SOURCE] [--threads THREADS] [--image IMAGE] [--dataset-path DATASET_PATH] [--runtime RUNTIME] [--log-level LEVEL] [--debug]
       $(basename "$0") [--mode auto|container|vm] ...
       $(basename "$0") UTIL_CD SOURCE [DATASET_PATH] [THREADS]

Command line args override environment variables.

Environment variables:
  EYEON_UTIL_CD
  EYEON_SOURCE
  EYEON_THREADS      Default: 8
  EYEON_IMAGE        Default: ghcr.io/llnl/peyeon:latest; override for dev/test images
  EYEON_DATASET_PATH Default: datasets.dataset_path from EyeOnData.toml
  EYEON_LOG_LEVEL    Default: WARNING
  EYEON_EYEONDATA_TOML Explicit path to EyeOnData.toml (overrides auto-discovery)
  EYEON_MODE         auto|container|vm (default: auto; auto selects vm when /etc/eyeon-appliance exists)
  EYEON_OWNER        Required when running as root unless passthrough is enabled
  EYEON_UID/GID      Explicit numeric owner override for runtime outputs
  EYEON_PASSTHROUGH_ROOT=1  Intentionally create root-owned outputs
  EYEON_CONTAINER_RUNTIME  Runtime override: docker or podman
  DEBUG=1            Print docker/env details and launch an interactive debug shell
EOF
}

print_command() {
  printf '%q ' "$@"
  printf '\n'
}

resolve_owner_ids() {
  local owner="$1"

  if ! id "$owner" >/dev/null 2>&1; then
    echo "EYEON_OWNER does not exist: $owner" >&2
    exit 2
  fi

  HOST_UID="$(id -u "$owner")"
  HOST_GID="$(id -g "$owner")"
}

resolve_runtime() {
  if [[ -n "$CONTAINER_RUNTIME" ]]; then
    case "$CONTAINER_RUNTIME" in
      docker|podman)
        return
        ;;
      *)
        echo "Unsupported container runtime: $CONTAINER_RUNTIME" >&2
        echo "Use docker or podman." >&2
        exit 2
        ;;
    esac
  fi

  local has_docker=0
  local has_podman=0
  local docker_path=""
  local podman_path=""

  docker_path="$(type -P docker 2>/dev/null || true)"
  podman_path="$(type -P podman 2>/dev/null || true)"

  if [[ -n "$docker_path" && -x "$docker_path" ]]; then
    has_docker=1
  fi

  if [[ -n "$podman_path" && -x "$podman_path" ]]; then
    has_podman=1
  fi

  if [[ "$has_docker" -eq 1 && "$has_podman" -eq 0 ]]; then
    CONTAINER_RUNTIME=docker
    return
  fi

  if [[ "$has_docker" -eq 0 && "$has_podman" -eq 1 ]]; then
    CONTAINER_RUNTIME=podman
    return
  fi

  if [[ "$has_docker" -eq 1 && "$has_podman" -eq 1 ]]; then
    echo "Both docker and podman are installed. Set EYEON_CONTAINER_RUNTIME or use --runtime." >&2
    exit 2
  fi

  echo "Neither docker nor podman is installed or available in PATH." >&2
  exit 2
}

resolve_mode() {
  local mode="$1"

  if [[ -z "$mode" || "$mode" == "auto" ]]; then
    if [[ -f /etc/eyeon-appliance ]]; then
      mode="vm"
    else
      mode="container"
    fi
  fi

  case "$mode" in
    container|vm)
      printf '%s\n' "$mode"
      return 0
      ;;
    *)
      echo "Unsupported mode: $mode" >&2
      echo "Use --mode auto|container|vm (or set EYEON_MODE)." >&2
      exit 2
      ;;
  esac
}

run_vm_parse() {
  local util_cd="$1"
  local source="$2"
  local dataset_path="$3"
  local threads="$4"
  local debug_mode="$5"
  local log_level="$6"

  if ! command -v eyeon >/dev/null 2>&1; then
    echo "eyeon is not installed or not in PATH." >&2
    exit 2
  fi

  # Create a structured name for the parsed batch of data using a timestamp and the UTIL_CD.
  local ts
  ts="$(date -u +'%Y%m%dT%H%M%SZ')"
  local o
  o="${ts}_${util_cd}"
  local output_dir
  output_dir="$dataset_path/$o"

  mkdir -p "$output_dir"

  local cmd=(eyeon parse -o "$output_dir" -t "$threads" -v "$log_level" "$source")
  local debug_command
  debug_command="$(printf '%q ' "${cmd[@]}")"
  debug_command="${debug_command% }"

  if [[ "$debug_mode" == "1" ]]; then
    echo "DEBUG=1" >&2
    echo "MODE=vm" >&2
    echo "UTIL_CD=$util_cd" >&2
    echo "SOURCE=$source" >&2
    echo "DATASET_PATH=$dataset_path" >&2
    echo "OUTPUT_DIR=$output_dir" >&2
    echo "THREADS=$threads" >&2
    echo "LOG_LEVEL=$log_level" >&2
    echo "EYEON_DEBUG_COMMAND=$debug_command" >&2
    echo "Command:" >&2
    print_command "${cmd[@]}" >&2
    EYEON_DEBUG_COMMAND="$debug_command" exec bash
  fi

  exec "${cmd[@]}"
}

run_container_parse() {
  local util_cd="$1"
  local source="$2"
  local dataset_path="$3"
  local threads="$4"
  local image="$5"
  local debug_mode="$6"
  local log_level="$7"

  # Owner/uid/gid/runtime are resolved from the global variables and exported values
  # earlier in the script.

  resolve_runtime

  # Create a structured name for the parsed batch of data using a timestamp and the UTIL_CD.
  local ts
  ts="$(date -u +'%Y%m%dT%H%M%SZ')"
  local o
  o="${ts}_${util_cd}"
  local output_dir
  output_dir="$dataset_path/$o"

  mkdir -p "$output_dir"

  if [[ "$EUID" -eq 0 && "$HOST_UID:$HOST_GID" != "0:0" ]]; then
    chown "$HOST_UID:$HOST_GID" "$output_dir"
  fi

  local container_cmd=(eyeon parse -o "/workdir/$o" -t "$threads" -v "$log_level" /source)
  local debug_command
  debug_command="$(printf '%q ' "${container_cmd[@]}")"
  debug_command="${debug_command% }"

  local runtime_cmd=("$CONTAINER_RUNTIME" run --rm)

  if [[ "$debug_mode" == "1" ]]; then
    if [[ -t 0 && -t 1 ]]; then
      runtime_cmd+=(-it)
    else
      runtime_cmd+=(-i)
    fi
  elif [[ -t 0 && -t 1 ]]; then
    runtime_cmd+=(-it)
  elif [[ -t 1 ]]; then
    runtime_cmd+=(-t)
  fi

  case "$CONTAINER_RUNTIME" in
    docker)
      runtime_cmd+=(
        -e "EYEON_UID=$HOST_UID"
        -e "EYEON_GID=$HOST_GID"
        -e "DEBUG=$debug_mode"
        -e "PYTHONUNBUFFERED=1"
        -e "TERM=${TERM:-xterm-256color}"
        -e "EYEON_DEBUG_COMMAND=$debug_command"
        -v "$source:/source:ro"
        -v "$dataset_path:/workdir:rw,Z"
        "$image"
      )
      ;;
    podman)
      runtime_cmd+=(
        -e "DEBUG=$debug_mode"
        -e "PYTHONUNBUFFERED=1"
        -e "TERM=${TERM:-xterm-256color}"
        -e "EYEON_DEBUG_COMMAND=$debug_command"
        -v "$source:/source:ro"
        -v "$dataset_path:/workdir:rw"
        "$image"
      )
      ;;
  esac

  if [[ "$debug_mode" == "1" ]]; then
    echo "DEBUG=1" >&2
    echo "MODE=container" >&2
    echo "RUNTIME=$CONTAINER_RUNTIME" >&2
    echo "IMAGE=$image" >&2
    echo "UTIL_CD=$util_cd" >&2
    echo "SOURCE=$source" >&2
    echo "DATASET_PATH=$dataset_path" >&2
    echo "OUTPUT_DIR=$output_dir" >&2
    echo "THREADS=$threads" >&2
    echo "LOG_LEVEL=$log_level" >&2
    echo "HOST_UID=$HOST_UID" >&2
    echo "HOST_GID=$HOST_GID" >&2
    echo "EYEON_DEBUG_COMMAND=$debug_command" >&2
    echo "Container command:" >&2
    print_command "${runtime_cmd[@]}" bash >&2
    exec "${runtime_cmd[@]}" bash
  fi

  exec "${runtime_cmd[@]}" "${container_cmd[@]}"
}

source_has_files() {
  [[ -n "$(find "$SOURCE" -type f -print -quit)" ]]
}

IMAGE="${EYEON_IMAGE:-ghcr.io/llnl/peyeon:latest}"
DATASET_PATH="${EYEON_DATASET_PATH:-}"
UTIL_CD="${EYEON_UTIL_CD:-}"
SOURCE="${EYEON_SOURCE:-}"
THREADS="${EYEON_THREADS:-8}"
LOG_LEVEL="${EYEON_LOG_LEVEL:-WARNING}"
MODE="${EYEON_MODE:-auto}"
OWNER_OVERRIDE="${EYEON_OWNER:-}"
HOST_UID="${EYEON_UID:-}"
HOST_GID="${EYEON_GID:-}"
PASSTHROUGH_ROOT="${EYEON_PASSTHROUGH_ROOT:-0}"
CONTAINER_RUNTIME="${EYEON_CONTAINER_RUNTIME:-}"
DEBUG_MODE="${DEBUG:-0}"
UTIL_CD_FLAG_SET=0
SOURCE_FLAG_SET=0
THREADS_FLAG_SET=0

POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --util-cd)
      if [[ $# -lt 2 || "$2" == -* ]]; then
        echo "Missing value for --util-cd" >&2
        usage
        exit 2
      fi
      UTIL_CD="${2:-}"
      UTIL_CD_FLAG_SET=1
      shift 2
      ;;
    --log-level)
      if [[ $# -lt 2 || "$2" == -* ]]; then
        echo "Missing value for --log-level" >&2
        usage
        exit 2
      fi
      LOG_LEVEL="${2:-}"
      shift 2
      ;;
    --dir)
      if [[ $# -lt 2 || "$2" == -* ]]; then
        echo "Missing value for --dir" >&2
        usage
        exit 2
      fi
      SOURCE="${2:-}"
      SOURCE_FLAG_SET=1
      shift 2
      ;;
    --threads)
      if [[ $# -lt 2 || "$2" == -* ]]; then
        echo "Missing value for --threads" >&2
        usage
        exit 2
      fi
      THREADS="${2:-}"
      THREADS_FLAG_SET=1
      shift 2
      ;;
    --image)
      if [[ $# -lt 2 || "$2" == -* ]]; then
        echo "Missing value for --image" >&2
        usage
        exit 2
      fi
      IMAGE="${2:-}"
      shift 2
      ;;
    --dataset-path)
      if [[ $# -lt 2 || "$2" == -* ]]; then
        echo "Missing value for --dataset-path" >&2
        usage
        exit 2
      fi
      DATASET_PATH="${2:-}"
      shift 2
      ;;
    --runtime)
      if [[ $# -lt 2 || "$2" == -* ]]; then
        echo "Missing value for --runtime" >&2
        usage
        exit 2
      fi
      CONTAINER_RUNTIME="${2:-}"
      shift 2
      ;;
    --mode)
      if [[ $# -lt 2 || "$2" == -* ]]; then
        echo "Missing value for --mode" >&2
        usage
        exit 2
      fi
      MODE="${2:-}"
      shift 2
      ;;
    --debug)
      DEBUG_MODE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      POSITIONAL+=("$@")
      break
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [[ ${#POSITIONAL[@]} -gt 4 ]]; then
  usage
  exit 2
fi

if [[ $UTIL_CD_FLAG_SET -eq 0 && ${#POSITIONAL[@]} -ge 1 ]]; then
  UTIL_CD="${POSITIONAL[0]}"
fi

if [[ $SOURCE_FLAG_SET -eq 0 && ${#POSITIONAL[@]} -ge 2 ]]; then
  SOURCE="${POSITIONAL[1]}"
fi

if [[ ${#POSITIONAL[@]} -ge 3 ]]; then
  if [[ $THREADS_FLAG_SET -eq 0 && "${POSITIONAL[2]}" =~ ^[0-9]+$ ]]; then
    THREADS="${POSITIONAL[2]}"
  else
    DATASET_PATH="${POSITIONAL[2]}"
  fi
fi

if [[ $THREADS_FLAG_SET -eq 0 && ${#POSITIONAL[@]} -ge 4 ]]; then
  THREADS="${POSITIONAL[3]}"
fi

if [[ -z "$UTIL_CD" || -z "$SOURCE" ]]; then
  usage
  exit 2
fi

if [[ -z "$DATASET_PATH" ]]; then
  SETTINGS_FILE="$(resolve_settings_file 2>/dev/null || true)"
  DATASET_PATH="$(read_dataset_path_from_toml)"
fi

if [[ -z "$DATASET_PATH" ]]; then
  DATASET_PATH=$HOME/data/eyeon
  echo "DATASET_PATH defaulting to $DATASET_PATH. To override, set datasets.dataset_path in EyeOnData.toml, EYEON_DATASET_PATH, or --dataset-path." >&2
fi

if [[ ! -d "$SOURCE" ]]; then
  echo "SOURCE is not a directory: $SOURCE" >&2
  exit 2
fi

if ! source_has_files; then
  echo "SOURCE does not contain any files: $SOURCE" >&2
  echo "Select the directory that contains the EyeOn files to parse, not an empty parent directory." >&2
  exit 2
fi

if ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [[ "$THREADS" -lt 1 ]]; then
  echo "THREADS must be a positive integer, got: $THREADS" >&2
  exit 2
fi

if [[ "$LOG_LEVEL" == "WARN" ]]; then
  LOG_LEVEL="WARNING"
fi

MODE="$(resolve_mode "$MODE")"

if [[ "$MODE" == "vm" ]]; then
  run_vm_parse "$UTIL_CD" "$SOURCE" "$DATASET_PATH" "$THREADS" "$DEBUG_MODE" "$LOG_LEVEL"
fi

if [[ -n "$OWNER_OVERRIDE" && (-n "$HOST_UID" || -n "$HOST_GID") ]]; then
  echo "Set either EYEON_OWNER or EYEON_UID/EYEON_GID, not both." >&2
  exit 2
fi

if [[ -n "$OWNER_OVERRIDE" ]]; then
  resolve_owner_ids "$OWNER_OVERRIDE"
elif [[ -n "$HOST_UID" || -n "$HOST_GID" ]]; then
  if [[ -z "$HOST_UID" || -z "$HOST_GID" ]]; then
    echo "EYEON_UID and EYEON_GID must both be set together." >&2
    exit 2
  fi
elif [[ "$EUID" -eq 0 ]]; then
  if [[ "$PASSTHROUGH_ROOT" == "1" ]]; then
    HOST_UID=0
    HOST_GID=0
  else
    echo "Running as root requires EYEON_OWNER or EYEON_UID/EYEON_GID." >&2
    echo "Set EYEON_PASSTHROUGH_ROOT=1 to intentionally create root-owned outputs." >&2
    exit 2
  fi
else
  HOST_UID="$(id -u)"
  HOST_GID="$(id -g)"
fi

if ! [[ "$HOST_UID" =~ ^[0-9]+$ && "$HOST_GID" =~ ^[0-9]+$ ]]; then
  echo "Resolved runtime UID/GID must be numeric, got: $HOST_UID:$HOST_GID" >&2
  exit 2
fi

resolve_runtime

run_container_parse "$UTIL_CD" "$SOURCE" "$DATASET_PATH" "$THREADS" "$IMAGE" "$DEBUG_MODE" "$LOG_LEVEL"
