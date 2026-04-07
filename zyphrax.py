import argparse
from vt_scan import scanfile
from metadata import get_file_metadata

parser = argparse.ArgumentParser(description="Analyze a file locally and optionally with VirusTotal")
parser.add_argument("file", help="Path to the file to analyze")
parser.add_argument("--vt", action="store_true", help="Perform VirusTotal scan")
args = parser.parse_args()

file_path = args.file

metadata = get_file_metadata(file_path)

print("\nFILE METADATA\n-------------")
for key, value in metadata.items():
    print(f"{key.capitalize().replace('_', ' ')}: {value}")

if args.vt:
    vt_results = scanfile(file_path)
    if vt_results:
        print("\nVIRUSTOTAL SCAN SUMMARY\n-------------")
        for key, value in vt_results.items():
            print(f"{key}: {value}")