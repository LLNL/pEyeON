# pEyeON

EyeON is a CLI tool that allows users to get software data pertaining to their machines by performing threat and inventory analysis. It can be used to quickly verify that the software and firmware used in OT environments are secure. 

<p align="center">
<img src="Photo/EyeON_logo.png" width="300" height="270">

## Motivation

Validation is important when installing new software. Existing tools use a hash/signature check to validate that the software has not been tampered. Knowing that the software works as intended saves a lot of time and energy, but just performing these hash/signature checks doesn't provide all the information needed to understand supply chain threats. 

EyeON provides an automated, consistent process across users to scan software files used for operational technologies. It's findings can be used to generate reports that can help in tracking software patterns to shed light on supply chain risks. This tool's main capabilities are focused on increasing the security of OT software. 

## Installation
```bash
git clone ssh://git@czgitlab.llnl.gov:7999/cir-software-assurance/peyeon.git
```
or 
```bash
git clone https://lc.llnl.gov/gitlab/cir-software-assurance/peyeon.git
```

### Dockerfile
This dockerfile contains all the pertinent tools specific to data extraction. The three tools mainly needed are ssdeep, libmagic, and tlsh. There are a couple variables that need to be changed in order for it to work.

Fix user permissions in eyeon.Dockerfile:
```bash
1. Change all instances of "50001" to "1000." 
There are 3 instances of it.

Ex. "&& groupadd -g 50001 xyz \" to "&& groupadd -g 1000 xyz \"

2. Change all instances of "xyz" to system_user_name. 
There are 6 instances of it. 

Ex. "&& groupadd -g 1000 xyz \" to "&& groupadd -g 1000 system_user_name \"

```
Add path variable at the bottom and point it to your current user directory:
```bash
ENV PATH=/home/<system_user_name>/.local/bin:$PATH
```

Build docker image:
```bash
docker build -t peyeon -f eyeon.Dockerfile .
```

Install EyeON in docker environment and then run docker container:
```bash
docker run -it -v $(pwd):/workdir peyeon /bin/bash
```
This attaches current code directory as work directory in the container. 
In the container:
```bash
cd into /workdir/tests directory 
run `rein` alias to build python dependencies 
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

EyeON consists of two parts - an observe call and a parse call. Observe.py works on a single file to return a suite of identifying metrics. Both of these can be run either from a library import or a CLI command.

#### Observe

1. This CLI command calls the observe function and makes an observation of a file. 

CLI command:

```bash
eyeon observe Obsidian.1.1.9.exe
```

Init file calls observe function in observe.py

```bash
obs = eyeon.observe.Observe("./tests/Obsidian.1.1.9.exe")
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

## Future Work
There will be a second part to this project, which will be to develop a cloud application that anonymizes and summarizes the findings to enable OT security analysis.
