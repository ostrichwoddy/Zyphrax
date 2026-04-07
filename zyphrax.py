import sys
from vt_scan import scanfile
from metadata import get_file_metadata

file_path = sys.argv[1]
# scanfile(file_path)
metadata = get_file_metadata(file_path)
for key, value in metadata.items():
    print(f"{key.capitalize().replace('_', ' ')}: {value}")

vt_results = scanfile(file_path)
if vt_results:
    print("\nVirusTotal Scan Summary:")
    for key, value in vt_results.items():
        print(f"{key}: {value}")