import requests
import time
import sys
import os
from dotenv import load_dotenv


# Load env
load_dotenv()

# ----- CONFIG -----
API_KEY = os.getenv("VT_API_KEY")
FILE_PATH = sys.argv[1]
POLL_INTERVAL = 10  # seconds between checks

# ----- STEP 1: Upload file -----
def upload_file(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": API_KEY.strip()}
    with open(file_path, "rb") as f:
        files = {"file": f}
        response = requests.post(url, headers=headers, files=files)
    data = response.json()
    return data["data"]["id"]  # analysis ID

# ----- STEP 2: Poll for results -----
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

# ----- MAIN -----
if __name__ == "__main__":
    analysis_id = upload_file(FILE_PATH)
    report_json = get_report(analysis_id)
    print(report_json)  # raw JSON output