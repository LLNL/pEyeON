# pEyeON

EyeON is a CLI tool that allows users to get software data pertaining to their machines by performing threat and inventory analysis. It can be used to quickly generate manifests of installed software or potential firmare patches. These manifests are then submitted to a database and LLNL can use them to continuously monitor OT software for threats.

[![CI Test Status](https://github.com/LLNL/pEyeON/actions/workflows/unittest.yml/badge.svg)](https://github.com/LLNL/pEyeON/actions/workflows/unittest.yml)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/LLNL/pEyeON/main.svg)]()
[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/LLNL/pEyeON/blob/main/LICENSE)

<p align="center">
<img src="Photo/EyeON_Mascot.png" width="300" height="270">

## Motivation

Validation is important when installing new software. Existing tools use a hash/signature check to validate that the software has not been tampered. Knowing that the software works as intended saves a lot of time and energy, but just performing these hash/signature checks doesn't provide all the information needed to understand supply chain threats. 

EyeON provides an automated, consistent process across users to scan software files used for operational technologies. Its findings can be used to generate reports that track software patterns, shedding light on supply chain risks. This tool's main capabilities are focused on increasing the visibility of OT software landscape. 

## Installation
Eyeon can also be run in linux or WSL.

```bash
git clone git@github.com:LLNL/pEyeON.git
```
or 
```bash
git clone https://github.com/LLNL/pEyeON.git
```

### Dockerfile
This dockerfile contains all the pertinent tools specific to data extraction. The main tools needed are `ssdeep`, `libmagic`, `tlsh`, and `detect-it-easy`. There are a couple variables that need to be changed in order for it to work.

Run docker build script
```bash
./docker-build.sh
```

Run docker run script
```bash
./docker-run.sh
```

This attaches current the code directory as a working directory in the container. Files that need to be scanned should go in "tests" folder. If running in a docker container, the eyeon root directory is mounted to "/workdir", so place samples in "/workdir/samples" or "/workdir/tests/samples".

Cd into workdir directory, install EyeON, and run 'rein' alias to build python dependencies:
```bash
cd workdir
rein
```

EyeON commands should work now.

## Usage

This section shows how to run the CLI component. 

1. Displays all arguments 
```bash
eyeon --help
```

2. Displays observe arguments 
```bash
eyeon observe --help
```

3. Displays parse arguments 
```bash
eyeon parse --help
```

EyeON consists of two parts - an observe call and a parse call. `observe.py` works on a single file to return a suite of identifying metrics, whereas `parse.py` expects a folder. Both of these can be run either from a library import or a CLI command.

#### Observe

1. This CLI command calls the observe function and makes an observation of a file. 

CLI command:

```bash
eyeon observe notepad++.exe
```

Init file calls observe function in observe.py

```bash
obs = eyeon.observe.Observe("./tests/binaries/x86/notepad++/notepad++.exe")
```
The observation will output a json file containing unique identifying information such as hashes, modify date, certificate info, etc.

Example json file:

```json
{
    "bytecount": 9381, 
    "filename": "demo.ipynb", 
    "signatures": {"valid": "N/A"}, 
    "imphash": "N/A", 
    "magic": "JSON text data", 
    "modtime": "2023-11-03 20:21:20", 
    "observation_ts": "2024-01-17 09:16:48", 
    "permissions": "0o100644", 
    "md5": "34e11a35c91d57ac249ff1300055a816", 
    "sha1": "9388f99f2c05e6e36b279dc2453ebea4bdc83242", 
    "sha256": "fa95b3820d4ee30a635982bf9b02a467e738deaebd0db1ff6a262623d762f60d", 
    "ssdeep": "96:Ui7ooWT+sPmRBeco20zV32G0r/R4jUkv57nPBSujJfcMZC606/StUbm/lGMipUQy:U/pdratRqJ3ZHStx4UA+I1jS"
}
```

#### Parse
parse.py calls observe recursively, returning an observation for each file in a directory. 

```bash
obs = eyeon.parse.Parse(args.dir)
```

#### Jupyter Notebook
If you want to run jupyter, the `./docker-run.sh` script exposes port 8888. Launch it from the `/workdir` or eyeon root directory via `jupyter notebook --ip=0.0.0.0 --no-browser` and open the `demo.ipynb` notebook for a quick demonstration.


#### Streamlit app
In the `src` directory, there exist the bones of a data exploration applet. To generate data for this, add the database flag like `eyeon parse -d tests/data/20240925-eyeon/dbhelpers/20240925-eyeon.db`. Then, if necessary, update the database path variable in the `src/streamlit/eyeon_settings.toml`. Note that the path needs to point to the grandparent directory of the `dbhelpers` directory. This is a specific path for the streamlit app; the streamlit directory has more information in its own README.


## Future Work
There will be a second part to this project, which will be to develop a cloud application that anonymizes and summarizes the findings to enable OT security analysis.

SPDX-License-Identifier: MIT
