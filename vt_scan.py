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
    Upload a file to VirusTotal and return analysis ID, SHA256, or existing analysis URL.
    """
    api_key = api_key or API_KEY
    if not api_key:
        return None

    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key.strip()}

    try:
        with open(file_path, "rb") as f:
            files = {"file": f}
            response = requests.post(url, headers=headers, files=files)
    except Exception:
        return None

    data = response.json()

    if response.status_code == 409:
        # File already submitted
        sha256 = data.get("meta", {}).get("file_info", {}).get("sha256")
        existing_url = data.get("error", {}).get("links", {}).get("self")
        if existing_url:
            return existing_url
        elif sha256:
            return sha256
        else:
            return None

    elif response.status_code != 200:
        return None

    if "error" in data:
        return None

    analysis_id = data.get("data", {}).get("id")
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
        except Exception:
            return None

        if response.status_code == 429:
            time.sleep(60)
            continue
        elif response.status_code != 200:
            return None

        data = response.json()
        if "error" in data:
            return None

        status = data.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return data
        else:
            print("\nWaiting for analysis to complete ..")
            time.sleep(POLL_INTERVAL)


def get_vt_summary_dict(vt_json):
    """
    Convert VT scan results into a dictionary with friendly names.
    """
    attributes = vt_json.get("data", {}).get("attributes", {})
    stats = attributes.get("stats", {})

    # Mapping of VT keys to friendly names
    key_map = {
        'malicious': 'Malware',
        'suspicious': 'Suspicious',
        'harmless': 'Safe',
        'undetected': 'Undetected',
        'type-unsupported': 'Unsupported Type',
        'failure': 'Scan Failures',
        'timeout': 'Timeouts'
    }

    summary = {display_name: stats.get(vt_key, 0) for vt_key, display_name in key_map.items()}

    # Add total vendors
    total_vendors = len(attributes.get('results', {}))
    summary['Total vendors'] = total_vendors

    return summary


def scanfile(file_path, api_key=None, return_summary=True):
    """
    Upload a file and return VT analysis report as a dictionary.
    """
    analysis_identifier = upload_file(file_path, api_key)
    if not analysis_identifier:
        return None

    report = get_report(analysis_identifier, api_key)
    if not report:
        return None

    if return_summary:
        return get_vt_summary_dict(report)
    else:
        return report


# ----------------- MAIN -----------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)

    file_path = sys.argv[1]
    result = scanfile(file_path)

    if result:
        for k, v in result.items():
            print(f"{k}: {v}")