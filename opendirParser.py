#!/usr/bin/env python3

import requests
import csv
import time
import os
import hashlib
import signal
import sys
import re
import zipfile
import subprocess
import logging

logging.basicConfig(filename='/home/ubuntu/opendirURLHaus/script.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MALWARE_DIR = os.path.join(BASE_DIR, "Malware")
IDS_FILE_PATH = os.path.join(BASE_DIR, "ids.txt")
OUTPUT_FILE_PATH = os.path.join(BASE_DIR, "output.txt")

def load_scanned_ids():
    logging.info("Loading scanned IDs.")
    if not os.path.exists(IDS_FILE_PATH):
        logging.warning(f"ID file {IDS_FILE_PATH} does not exist.")
        return []
    with open(IDS_FILE_PATH, "r") as file:
        return file.read().splitlines()

def prune_oldest_ids(ids_list, threshold=10000, prune_count=3000):
    logging.info(f"Checking if ID list exceeds the threshold of {threshold}.")
    if len(ids_list) > threshold:
        return ids_list[prune_count:]
    return ids_list

def save_all_ids(ids_list):
    logging.info("Saving all IDs to file.")
    with open(IDS_FILE_PATH, "w") as file:
        for id in ids_list:
            file.write(f"{id}\n")

def strip_ansi_escape(data):
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', data)

def dual_print(*args, **kwargs):
    original_print(*args, **kwargs)
    with open(OUTPUT_FILE_PATH, "a") as output_file:  # Use OUTPUT_FILE_PATH here
        stripped_args = [strip_ansi_escape(str(arg)) for arg in args]
        original_print(*stripped_args, file=output_file, **kwargs)

# Overwrite the built-in print function
original_print = print
print = dual_print

CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_online/"
VT_URL_V2 = "https://www.virustotal.com/vtapi/v2/file/report"
VT_API_KEY = ""

def signal_handler(sig, frame):
    original_print("\n[ERROR] Interrupted by user. Exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTSTP, signal_handler)

def display_intro():
    spider_art = r"""
                  
                            _ _                                       
                           | (_)                                      
  ___  _ __   ___ _ __   __| |_ _ __   _ __   __ _ _ __ ___  ___ _ __ 
 / _ \| '_ \ / _ \ '_ \ / _` | | '__| | '_ \ / _` | '__/ __|/ _ \ '__|
| (_) | |_) |  __/ | | | (_| | | |    | |_) | (_| | |  \__ \  __/ |   
 \___/| .__/ \___|_| |_|\__,_|_|_|    | .__/ \__,_|_|  |___/\___|_|   
      | |                             | |                             
      |_|                             |_|                             
      
 
                                                        
    """
    print(spider_art)

def download_csv():
    print("[INFO] Downloading CSV data...")
    response = requests.get(CSV_URL)
    response.raise_for_status()

    with open(os.path.join(BASE_DIR, "malware_urls.csv"), "wb") as f:
        f.write(response.content)
    print("[INFO] CSV data downloaded successfully.")

def fetch_file(url):
    logging.info(f"Attempting to fetch file from URL: {url}")
    print(f"[PROGRESS] Fetching file from {url}")
    try:
        response = requests.get(url, stream=True, timeout=15)
        response.raise_for_status()

        # Check for the Content-Type header
        content_type = response.headers.get('Content-Type', '')
        if 'text' in content_type or 'html' in content_type:
            print(f"[WARNING] Unexpected Content-Type {content_type} for URL {url}. Skipping...")
            return None, None

        filename = url.split("/")[-1] or 'unknown_filename'
        print(f"[PROGRESS] Detected filename: {filename}")
        return filename, response.content
    except (requests.RequestException, KeyboardInterrupt) as e:
        print(f"[ERROR] Error fetching {url}: {e}")
        return None, None

def calculate_hashes(content):
    md5 = hashlib.md5(content).hexdigest()
    sha1 = hashlib.sha1(content).hexdigest()
    sha256 = hashlib.sha256(content).hexdigest()
    return md5, sha1, sha256

def check_virustotal_v2(sha256_hash):
    logging.info(f"Checking file with SHA256 {sha256_hash} on VirusTotal.")
    params = {
        "apikey": VT_API_KEY,
        "resource": sha256_hash
    }
    response = requests.get(VT_URL_V2, params=params)
    if response.status_code == 200:
        json_response = response.json()
        if json_response.get("response_code") == 1:
            if json_response.get("positives", 0) > 0:
                print(f"[VERDICT] File with SHA256 {sha256_hash} is already known to be malicious. Removing...")
                return True
            else:
                print(f"[VERDICT] File with SHA256 {sha256_hash} is unknown. Saving...")
                return False
        else:
            print(f"[ERROR] File with SHA256 {sha256_hash} is not in VirusTotal database. Treating as unknown.")
            return False
    else:
        print(f"[ERROR] Error checking with VirusTotal: {response.status_code} {response.reason}")
        return False

def zip_file(file_dir, filename):
    """Zip the file and then remove the original file."""
    with zipfile.ZipFile(os.path.join(file_dir, f"{filename}.zip"), 'w') as zipf:
        zipf.write(os.path.join(file_dir, filename), filename)
    os.remove(os.path.join(file_dir, filename))
    print(f"[STATUS] File {filename} zipped.")

def main():
    display_intro()
    time.sleep(2)
    already_scanned_ids = load_scanned_ids()

    # Prune old IDs if needed
    already_scanned_ids = prune_oldest_ids(already_scanned_ids)

    if not os.path.exists(MALWARE_DIR):
        os.mkdir(MALWARE_DIR)

    download_csv()

    with open(os.path.join(BASE_DIR, "malware_urls.csv"), "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        next(reader)  # Skip header

        for row in reversed(list(reader)):
            id = row[0]  # Extracting the ID

            # Check and skip already scanned IDs
            if id in already_scanned_ids:
                logging.debug(f"ID {id} already scanned. Skipping.")
                continue

            if len(row) <= 2:
                print(f"[WARNING] Skipping malformed row in CSV: {row}")
                continue

            date_added = row[1]
            url = row[2]
            threat = row[5]
            tags = row[6]
            print("="*50)
            print(f"[PROGRESS] Processing URL: {url}")

            filename, content = fetch_file(url)
            if filename and content:
                # Use the ID for the folder name instead of the filename
                file_dir = os.path.join(MALWARE_DIR, id)
                if not os.path.exists(file_dir):
                    os.mkdir(file_dir)
                
                with open(os.path.join(file_dir, filename), "wb") as file:
                    file.write(content)
                with open(os.path.join(file_dir, "info.txt"), "w") as info_file:
                    info_file.write(f"Date Added: {date_added}\nURL: {url}\nThreat: {threat}\nTags: {tags}\n")

                md5, sha1, sha256 = calculate_hashes(content)
                print(f"[HASH] MD5: {md5}")
                print(f"[HASH] SHA1: {sha1}")
                print(f"[HASH] SHA256: {sha256}")

                if check_virustotal_v2(sha256):
                    os.remove(os.path.join(file_dir, filename))
                    os.remove(os.path.join(file_dir, "info.txt"))
                    os.rmdir(file_dir)
                else:
                    zip_file(file_dir, filename)
                    
            # Append the ID after processing the URL
            already_scanned_ids.append(id)
                    
    print("[INFO] Script completed.")
    print("[INFO] Starting push2MISP.py script...")
    try:
        subprocess.check_call(["/usr/bin/python3", "push2MISP.py"])
        print("[INFO] Push2MISP.py script completed successfully.")
    except subprocess.CalledProcessError:
        print("[ERROR] Error occurred while executing push2MISP.py.")

    # Save the updated list of IDs
    save_all_ids(already_scanned_ids)

if __name__ == "__main__":
    with open(OUTPUT_FILE_PATH, "w") as f:
        pass
    try:
        main()
    except KeyboardInterrupt:
        original_print("\n[ERROR] Interrupted by user. Exiting...")
        logging.error("Script interrupted by user.")