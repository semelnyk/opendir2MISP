import os
import base64
import hashlib
import time
import shutil
import logging
from pymisp import PyMISP, MISPEvent
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MISP_URL = ""
MISP_KEY = ""
MISP_VERIFYCERT = True

def display_misp_upload_progress():
    ascii_art = r"""
	
             _                 _ _               _         ___  ________ ___________     
            | |               | (_)             | |        |  \/  |_   _/  ___| ___ \    
 _   _ _ __ | | ___   __ _  __| |_ _ __   __ _  | |_ ___   | .  . | | | \ `--.| |_/ /    
| | | | '_ \| |/ _ \ / _` |/ _` | | '_ \ / _` | | __/ _ \  | |\/| | | |  `--. \  __/     
| |_| | |_) | | (_) | (_| | (_| | | | | | (_| | | || (_) | | |  | |_| |_/\__/ / |_ _ _ _ 
 \__,_| .__/|_|\___/ \__,_|\__,_|_|_| |_|\__, |  \__\___/  \_|  |_/\___/\____/\_(_|_|_|_)
      | |                                 __/ |                                          
      |_|                                |___/                                           
	  
	  
    """
    print(ascii_art)

def init_misp():
    try:
        return PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
    except Exception as e:
        logging.error(f"Failed to initialize MISP connection: {e}")
        print(f"[ERROR] Failed to initialize MISP connection: {e}")
        sys.exit(1)

def create_misp_event(misp):
    try:
        event = MISPEvent()
        event.info = f"URLHaus open directories {datetime.now().strftime('%Y-%m-%d')}"
        event.distribution = 1
        event.threat_level_id = 2
        event.analysis = 0
        event.add_tag("tlp:amber")
        event.add_tag("originalSource:CTI")
        event.add_tag("URLHaus/abuse.ch")
        event.add_tag('admiralty-scale:source-reliability="b"')
        event.add_tag('misp:event-type="automatic-analysis"')
        event.add_tag("opendir")

        result = misp.add_event(event)
        if 'Event' in result:
            event_id = result['Event']['id']
            print(f"[SUCCESS] MISP Event created with ID: {event_id}")
            return event_id
        else:
            print("[ERROR] Failed to create MISP Event.")
            if 'errors' in result:
                for error in result['errors']:
                    print(f"[ERROR] {error}")
            return None
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred during MISP event creation: {e}")
        return None

def read_info_txt(directory):
    info_file_path = os.path.join(directory, "info.txt")
    if os.path.exists(info_file_path):
        with open(info_file_path, "r") as info_file:
            return info_file.read()
    return ""

def compute_hashes(data):
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha1, sha256

def add_file_to_misp_event(misp, event_id, file_dir, filename):
    try:
        with open(os.path.join(file_dir, filename), "rb") as f:
            data = f.read()

        md5, sha1, sha256 = compute_hashes(data)

        # Encode the file data to base64
        b64_data = base64.b64encode(data).decode('utf-8')

        info_txt_content = read_info_txt(file_dir)
        formatted_comment = (f"MD5: {md5}\n"
                             f"SHA1: {sha1}\n"
                             f"SHA256: {sha256}\n"
                             f"{info_txt_content}")
        attribute = {
            'type': 'attachment',
            'value': filename,
            'data': b64_data,
            'comment': formatted_comment,
            'Tag': [
                {"name": "tlp:amber"},
                {'name': 'originalSource:CTI'},
                {"name": "URLHaus/abuse.ch"},
                {'name': 'admiralty-scale:source-reliability="b"'},
                {'name': 'misp:event-type="automatic-analysis"'},
                {"name": "opendir"}
            ]
        }
        
        result = misp.add_attribute(event_id, attribute)
        if 'Attribute' in result:
            print(f"[SUCCESS] Added '{filename}' to MISP event {event_id}")
        else:
            print(f"[ERROR] Error adding '{filename}' to MISP event")
    except Exception as e:
        logging.error(f"Error adding '{filename}' to MISP event: {e}")
        print(f"[ERROR] Error adding '{filename}' to MISP event:", e)
        
def cleanup():
    malware_folder_path = "Malware"
    if os.path.exists(malware_folder_path) and os.path.isdir(malware_folder_path):
        shutil.rmtree(malware_folder_path)
        print(f"[CLEANUP] Deleted folder: {malware_folder_path}")
       
    malware_file_path = "malware_urls.csv"
    if os.path.exists(malware_file_path):
        os.remove(malware_file_path)
        print(f"[CLEANUP] Deleted file: {malware_file_path}")

def main():
    try:
        display_misp_upload_progress()
        time.sleep(2)
        misp = init_misp()
        event_id = create_misp_event(misp)
        if event_id:
            malware_dir = "Malware"
            for root, _, files in os.walk(malware_dir):
                for filename in files:
                    if filename in ["info.txt", "output.txt"]:
                        continue
                    add_file_to_misp_event(misp, event_id, root, filename)
        cleanup()
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()

