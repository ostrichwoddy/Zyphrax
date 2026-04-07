import requests
import time
import sys
import os
from dotenv import load_dotenv

# ---------------- CONFIG ----------------
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
POLL_INTERVAL = 60  # seconds

# ---------------- UTILS ----------------
def upload_file(file_path, api_key=None):
    """
    Upload a file to VirusTotal and return analysis ID or existing SHA256.
    """
    api_key = api_key or API_KEY
    if not api_key:
        print("❌ No API key provided. Set VT_API_KEY or pass api_key argument.")
        return None

    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key.strip()}

    try:
        with open(file_path, "rb") as f:
            files = {"file": f}
            response = requests.post(url, headers=headers, files=files)
    except Exception as e:
        print(f"❌ Failed to open or upload file: {e}")
        return None

    data = response.json()

    if response.status_code == 409:
        # Already submitted
        sha256 = data.get("meta", {}).get("file_info", {}).get("sha256")
        existing_url = data.get("error", {}).get("links", {}).get("self")
        print(f"⚠️ File already submitted. SHA256: {sha256}")

        if existing_url:
            return existing_url
        elif sha256:
            return sha256
        else:
            print("❌ Could not determine existing analysis ID or SHA256. Exiting.")
            return None

    elif response.status_code != 200:
        print(f"❌ HTTP Error {response.status_code} uploading file:")
        print(response.text)
        return None

    if "error" in data:
        err = data["error"]
        print(f"❌ API Error: {err.get('code')} - {err.get('message')}")
        return None

    analysis_id = data.get("data", {}).get("id")
    if not analysis_id:
        print("❌ Unexpected response format:", data)
        return None

    return analysis_id


def get_report(analysis_identifier, api_key=None):
    """
    Poll VirusTotal for analysis results until completion.
    Accepts analysis ID, SHA256 hash, or full self-link URL.
    """
    api_key = api_key or API_KEY
    headers = {"x-apikey": api_key.strip()}

    # Determine URL
    if analysis_identifier.startswith("http"):
        url = analysis_identifier
    elif len(analysis_identifier) == 64:  # SHA256 fallback
        url = f"https://www.virustotal.com/api/v3/files/{analysis_identifier}/analysis"
    else:
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_identifier}"

    while True:
        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            print(f"❌ Failed to fetch report: {e}")
            return None

        if response.status_code == 429:
            print("🚫 Rate limit reached. Waiting 60 seconds...")
            time.sleep(60)
            continue
        elif response.status_code != 200:
            print(f"❌ HTTP Error {response.status_code} fetching report:")
            print(response.text)
            return None

        data = response.json()
        if "error" in data:
            err = data["error"]
            print(f"❌ API Error fetching report: {err.get('code')} - {err.get('message')}")
            return None

        status = data.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return data
        else:
            print("⏳ Waiting for analysis to complete...")
            time.sleep(POLL_INTERVAL)


def print_vt_summary(vt_json):
    """
    Print a readable summary of the VT scan results.
    """
    data = vt_json.get("data", {})
    attributes = data.get("attributes", {})
    meta = vt_json.get("meta", {})

    file_info = meta.get('file_info', {})
    print(f"\nFile size: {file_info.get('size')} bytes")
    print(f"MD5: {file_info.get('md5')}")
    print(f"SHA1: {file_info.get('sha1')}")
    print(f"SHA256: {file_info.get('sha256')}")

    stats = attributes.get('stats', {})
    print("\nScan Summary:")

    # Original keys from VT
    vt_keys = ['malicious', 'suspicious', 'harmless', 'undetected', 'type-unsupported', 'failure', 'timeout']

    # Friendly mapping
    key_map = {
        'malicious': 'Malware',
        'suspicious': 'Suspicious',
        'harmless': 'Safe',
        'undetected': 'Undetected',
        'type-unsupported': 'Unsupported Type',
        'failure': 'Scan Failures',
        'timeout': 'Timeouts'
    }

    for key in vt_keys:
        display_name = key_map.get(key, key)
        print(f"{display_name}: {stats.get(key, 0)}")

    total_vendors = len(attributes.get('results', {}))
    print(f"Total vendors: {total_vendors}")


def scanfile(file_path, api_key=None, print_summary=True):
    """
    Upload a file and print VT analysis report.
    """
    analysis_identifier = upload_file(file_path, api_key)
    if not analysis_identifier:
        print("❌ Upload failed. Exiting.")
        return None

    report = get_report(analysis_identifier, api_key)
    if not report:
        print("❌ Could not retrieve report. Exiting.")
        return None

    if print_summary:
        print_vt_summary(report)
    else:
        print(report)

    return report


# ----------------- MAIN -----------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("❌ Usage: python vt_scan.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    scanfile(file_path)