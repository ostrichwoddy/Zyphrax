import requests
import time
import sys
import os
from dotenv import load_dotenv

# Configurations
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
FILE_PATH = sys.argv[1]
POLL_INTERVAL = 10

# Function to upload file to vt
def upload_file(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": API_KEY.strip()}
    with open(file_path, "rb") as f:
        files = {"file": f}
        response = requests.post(url, headers=headers, files=files)
    data = response.json()
    return data["data"]["id"]  # analysis ID

# Function to poll for results
def get_report(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": API_KEY}
    while True:
        response = requests.get(url, headers=headers)
        data = response.json()
        status = data["data"]["attributes"]["status"]
        if status == "completed":
            return data  # JSON report
        else:
            print("⏳ Waiting for analysis to complete...")
            time.sleep(POLL_INTERVAL)

# Function to print result data
def print_vt_summary(vt_json):
    data = vt_json.get("data", {})
    attributes = data.get("attributes", {})
    meta = vt_json.get("meta", {})

    # File info
    file_info = meta.get('file_info', {})
    size = file_info.get('size')
    md5 = file_info.get('md5')
    sha1 = file_info.get('sha1')
    sha256 = file_info.get('sha256')

    print(f"File size: {size} bytes")
    print(f"MD5: {md5}")
    print(f"SHA1: {sha1}")
    print(f"SHA256: {sha256}")

    # Scan stats
    stats = attributes.get('stats', {})
    malware = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    harmless = stats.get('harmless', 0)
    undetected = stats.get('undetected', 0)
    type_unsupported = stats.get('type-unsupported', 0)
    failure = stats.get('failure', 0)
    timeout = stats.get('timeout', 0)

    # Total vendors = count of engines in results
    results = attributes.get('results', {})
    total_vendors = len(results)

    print("\nScan Summary:")
    print(f"Malware: {malware}")
    print(f"Suspicious: {suspicious}")
    print(f"Harmless: {harmless}")
    print(f"Undetected: {undetected}")
    print(f"Type-unsupported: {type_unsupported}")
    print(f"Failure: {failure}")
    print(f"Timeout: {timeout}")
    print(f"Total vendors: {total_vendors}")

# ----- MAIN -----

if __name__ == "__main__":
    analysis_id = upload_file(FILE_PATH)
    report_json = get_report(analysis_id)
    print_vt_summary(report_json) # raw JSON output
    # print(report_json)