import requests
import time
import sys
import os
import hashlib

# ----- CONFIG -----
POLL_INTERVAL = 10  # seconds between checks

# ----- HELPER FUNCTIONS -----

def compute_sha256(file_path):
    """Compute SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def upload_file(file_path, api_key):
    """Upload file to VirusTotal and return analysis ID."""
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key.strip()}

    with open(file_path, "rb") as f:
        files = {"file": f}
        response = requests.post(url, headers=headers, files=files)

    print("\nUpload response code:", response.status_code)
    print("Upload response text:", response.text)

    try:
        data = response.json()
    except Exception as e:
        print("Failed to parse JSON:", e)
        print("Raw response:", response.text)
        sys.exit(1)

    if "data" not in data:
        print("Error: 'data' not found in response. Full response:", data)
        sys.exit(1)

    return data["data"]["id"]

def get_report(analysis_id, api_key):
    """Poll VirusTotal until analysis is complete and return JSON report."""
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": api_key.strip()}

    while True:
        response = requests.get(url, headers=headers)
        try:
            data = response.json()
        except Exception as e:
            print("Failed to parse JSON:", e)
            print("Raw response:", response.text)
            time.sleep(POLL_INTERVAL)
            continue

        if "data" not in data or "attributes" not in data["data"]:
            print("Unexpected response structure:", data)
            time.sleep(POLL_INTERVAL)
            continue

        status = data["data"]["attributes"]["status"]
        if status == "completed":
            return data
        else:
            print("⏳ Waiting for analysis to complete...")
            time.sleep(POLL_INTERVAL)

def check_file_report(file_hash, api_key):
    """Check if file has already been scanned; return report if available."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key.strip()}
    response = requests.get(url, headers=headers)

    try:
        data = response.json()
    except Exception:
        return None

    if "data" in data:
        return data
    else:
        return None

# ----- MAIN -----

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python main.py <file_path> <api_key>")
        sys.exit(1)

    FILE_PATH = sys.argv[1]
    API_KEY = sys.argv[2]

    if not os.path.exists(FILE_PATH):
        print(f"Error: File {FILE_PATH} does not exist.")
        sys.exit(1)

    file_hash = compute_sha256(FILE_PATH)
    print(f"SHA256 of file: {file_hash}")

    # Check if file already scanned
    existing_report = check_file_report(file_hash, API_KEY)
    if existing_report:
        print("File already scanned. Using existing report.")
        report_json = existing_report
    else:
        print("File not scanned yet. Uploading...")
        analysis_id = upload_file(FILE_PATH, API_KEY)
        report_json = get_report(analysis_id, API_KEY)

    print("\n===== VirusTotal JSON Report =====")
    print(report_json)