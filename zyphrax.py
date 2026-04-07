import argparse
from vt_scan import scanfile
from metadata import get_file_metadata

import re

def analyze_metadata(metadata):
    """
    Analyze file metadata and assign a risk score.
    Checks: entropy, executable masquerade, suspicious filename, suspicious strings.
    Returns dict with score, verdict, reasoning.
    """
    score = 0
    reasoning = []

    # ----------------- 1. High entropy -----------------
    entropy = metadata.get("entropy", 0)
    if entropy > 7.5:  # typical threshold for packed/encrypted binaries
        score += 3
        reasoning.append(f"High entropy ({entropy:.2f})")

    # ----------------- 2. Executable masquerade -----------------
    common_exec_exts = {".exe", ".bin", ".sh", ".bat", ".cmd", ".elf", ".py"}
    apparent_ext = metadata.get("apparant_extension", "").lower()
    is_exec = metadata.get("executable", False)
    if is_exec and apparent_ext not in common_exec_exts:
        score += 2
        reasoning.append(f"Executable masquerade (extension: {apparent_ext})")

    # ----------------- 3. Suspicious filename -----------------
    suspicious_keywords = ["revshell", "hack", "payload", "malware", "backdoor", "exploit"]
    filename = metadata.get("filename", "").lower()
    if any(keyword in filename for keyword in suspicious_keywords):
        score += 2
        reasoning.append(f"Suspicious filename ({filename})")

    # ----------------- 4. Suspicious strings -----------------
    suspicious_strings_patterns = [
        r"/bin/sh", r"socket", r"execve", r"connect", r"dup2", r"system", r"wget", r"curl",
        r"inet_addr", r"htons", r"bash", r"nc", r"cmd.exe"
    ]
    strings = metadata.get("strings", [])
    matches = sum(any(re.search(pattern, s) for pattern in suspicious_strings_patterns) for s in strings)
    if matches > 0:
        score += min(matches, 5)  # cap contribution from strings to avoid overweight
        reasoning.append(f"Suspicious strings detected ({matches})")

    # ----------------- Verdict -----------------
    if score >= 6:
        verdict = "Malware"
    elif score >= 3:
        verdict = "Suspicious"
    else:
        verdict = "Probably Safe"

    return {
        "Score": score,
        "Verdict": verdict,
        "Reasoning": reasoning
    }

parser = argparse.ArgumentParser(description="Analyze a file locally and optionally with VirusTotal")
parser.add_argument("file", help="Path to the file to analyze")
parser.add_argument("--vt", action="store_true", help="Perform VirusTotal scan")
parser.add_argument("--strings", action="store_true", help="Print extracted strings from file")
args = parser.parse_args()

file_path = args.file

metadata = get_file_metadata(file_path)

# Print metadata
print("\nFILE METADATA\n-------------")
for key, value in metadata.items():
    if key == "strings":
        print(f"Strings count: {len(value)}")
        continue
    print(f"{key.capitalize().replace('_', ' ')}: {value}")

# Print strings
if args.strings and metadata.get("strings"):
    print("\nSTRINGS OUTPUT\n-------------")
    for s in metadata["strings"]:
        print(s)

# Print analysis of metadata
metadata_verdict = analyze_metadata(metadata)
print("\nMETADATA ANALYSIS\n-------------")
for key, value in metadata_verdict.items():
    if key == "Reasoning" and len(value) == 0:
        value = "Metadata analysis did not flag anything"
    print(f"{key}: {value}")


if args.vt:
    vt_results = scanfile(file_path)
    if vt_results:
        print("\nVIRUSTOTAL SCAN SUMMARY\n-------------")
        for key, value in vt_results.items():
            print(f"{key}: {value}")