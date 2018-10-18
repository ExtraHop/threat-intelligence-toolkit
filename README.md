# Threat Intelligence Toolkit

## Description
Automate generating or pulling threat intelligence Structured Threat Information Expression (STIX) files from a flat file or from a TAXII server and uploading a threat collection to an ECA and multiple EDAs via the REST API. By uploading STIX files, you can add a threat collection to your ExtraHop Discover and Command appliances. Threat collections enable you to identify suspicious hosts, IP addresses, and URIs on your network.

## Usage
Specify an output directory, threat collection name, ECA/EDA details, and other optional config via the command line then the script either generates a STIX file or polls the TAXII server (defaults to anomali limo intel feed), saves the stix files in a gzipped tar file (tgz), and uploads the threat collection to the specified Reveal(x) ECA/EDAs.

**This script solely serves as example code and is made available without any support or warranty.**

## Requirements
- python 3.6+
- [pip](https://pip.pypa.io/en/stable/installing/)

## Installation
- pip install cabby==0.1.20
- pip install stix==1.2.0.6

## Example Running Commands
You will need to update the example output paths, collection names, IP addresses, hostnames, and API keys below to match your environment.

- View usage and all possible command line arguments
  - `python3 threat_intelligence_toolkit.py -h`

- Download, tgz, and upload all collections from the default anomali limo TAXII server to an EDA
  - `python3 threat_intelligence_toolkit.py -o ~/output_folder -tc example_collection --eda 172.16.1.2 3Hb7EpHRqb2EpnS7iweHgR5F3sf False`

- Download, tgz, and upload all collections from the default anomali limo TAXII server to an ECA and multiple EDAs
  - `python3 threat_intelligence_toolkit.py -o ~/output_folder -tc example_collection --eca 172.16.1.1 3Hb7EpHRqb2EpnS7iweHgR5F3sg True --eda 172.16.1.2 3Hb7EpHRqb2EpnS7iweHgR5F3sf False --eda 172.16.1.3 3Hb7EpHRqb2EpnS7iweHgR5F3sf False`

- Download and tgz all collections from the default anomali limo TAXII server to be uploaded manually
  - `python3 threat_intelligence_toolkit.py -o ~/output_folder -tc example_collection`

- Download and tgz a specific list of collections from the default anomali limo TAXII server to be uploaded manually
  - `python3 threat_intelligence_toolkit.py -o ~/output_folder -tc example_collection --taxii-collections Abuse_ch_Ransomware_IPs_F135 Phish_Tank_F107`

- Download, tgz, and upload all collections from a specific taxii server to an EDA
  - `python3 threat_intelligence_toolkit.py -o ~/output_folder -tc example_collection --taxii-server hailataxii.com /taxii-discovery-service False --basic-user guest --basic-pw guest --days 90 --eda 172.16.1.2 3Hb7EpHRqb2EpnS7iweHgR5F3sf False`

- Generate a STIX file from a flat file, tgz, and upload to an EDA
  - `python3 threat_intelligence_toolkit.py -o ~/output_folder -tc example_collection --generate-stix --input-file https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/MiningServerIPList.txt --list-type ip --eda 172.16.1.2 3Hb7EpHRqb2EpnS7iweHgR5F3sf False`

## Notes
- One ECA and multiple EDAs can be provided.  If updating more than one ECA is required then the script must be ran multiple times
- The script uses the ExtraHop REST API threatcollections PUT endpoint to create the threat collection if it does not exist yet or to overwrite the threat collection if it already exists, so be sure to set -tc appropriately
- A timestamped tgz file will be created in the specified output directory (e.g. mycollection_2018-06-25_12-32-57.tgz)
- Running in verbose mode (-v) will output to the log the names of all of the available collections on a taxii server

## Logging
The script logs to a file named threat_intel_toolkit.log which is created in the output directory specified
