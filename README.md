# opendir2MISP
This repository contains Python scripts designed for downloading potentially malicious files from open directories sourced from URLHAUS and uploading these files to a MISP. The primary purpose is to automate the process of gathering files from open directories and reporting them to MISP, excluding those that are flagged as malicious by VirusTotal. The main idea behind this repository is to automate the process of collecting and analyzing potentially malicious files. The repository contains two Python scripts that work in tandem to achieve this:

**Malware Sample Downloader (opendirParser.py)**: This script downloads a CSV file containing URLs associated with potential malware samples. It then fetches the files from these URLs, checks their reputation on VirusTotal, and makes decisions on whether to keep or remove them based on their reputation. Additionally, it maintains a log of the process.

**MISP Uploader (push2MISP.py)**: This script connects to a MISP instance and creates a new event to upload information about the collected malware samples. It processes the files, computes their hashes, and adds them as attributes to the MISP event. After the upload, it cleans up any temporary files and directories.

## Prerequisites

Before running the scripts in this repository, ensure that you have the following prerequisites installed and configured:
```
pip install requests
pip install pymisp
```
VirusTotal API Key: You need a VirusTotal API key to check the reputation of downloaded files. Replace the VT_API_KEY variable in the script with your API key.

MISP Configuration: You need to provide the configuration for your MISP instance, including the MISP URL and API key. Set the MISP_URL and MISP_KEY variables in the misp_uploader.py script with the appropriate values.

## How to Run
```
python3 opendirParser.py
```
The script will fetch files from open directories and exclude those flagged as malicious by VirusTotal. After successfully downloading the files, it will automatically trigger the execution of push2MISP.py. Note: You do not need to manually run push2MISP.py as it will be executed automatically upon completing the download process.
