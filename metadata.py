import os
import hashlib
import mimetypes
import math
from datetime import datetime
import magic  # pip install python-magic
import re


def extract_strings(file_path, min_length=4):
    """
    Extract printable ASCII strings from a file.

    Args:
        file_path (str): Path to the file.
        min_length (int): Minimum string length to include.

    Returns:
        List[str]: A list of strings found in the file.
    """
    with open(file_path, "rb") as f:
        data = f.read()
    # Match sequences of printable ASCII characters
    strings = re.findall(rb"[ -~]{%d,}" % min_length, data)
    return [s.decode(errors='ignore') for s in strings]

def calculate_entropy(file_path):
    """Calculate Shannon entropy of a file."""
    with open(file_path, "rb") as f:
        data = f.read()
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    entropy = 0
    length = len(data)
    for count in byte_counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def hash_file(file_path, algo="sha256"):
    """Compute hash (md5, sha1, sha256) of a file."""
    h = hashlib.new(algo)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def detect_actual_filetype(file_path):
    """Detect the real file type using magic bytes."""
    try:
        mime = magic.Magic(mime=True)
        return mime.from_file(file_path)
    except Exception as e:
        return f"Unknown ({e})"

def get_file_metadata(file_path):
    """Return a dictionary of metadata for a file."""
    metadata = {}
    metadata["filename"] = os.path.basename(file_path)
    metadata["apparent_extension"] = os.path.splitext(file_path)[1].lower()
    metadata["file_size"] = os.path.getsize(file_path)
    metadata["filetype"] = mimetypes.guess_type(file_path)[0] or "Unknown"
    metadata["Magic bytes filetype"] = detect_actual_filetype(file_path)
    metadata["entropy"] = calculate_entropy(file_path)
    metadata["md5"] = hash_file(file_path, "md5")
    metadata["sha1"] = hash_file(file_path, "sha1")
    metadata["sha256"] = hash_file(file_path, "sha256")

    # Optional: timestamps and permissions
    stats = os.stat(file_path)
    metadata["created"] = datetime.fromtimestamp(stats.st_ctime).isoformat()
    metadata["modified"] = datetime.fromtimestamp(stats.st_mtime).isoformat()
    metadata["readable"] = os.access(file_path, os.R_OK)
    metadata["writable"] = os.access(file_path, os.W_OK)
    metadata["executable"] = os.access(file_path, os.X_OK)

    metadata["strings"] = extract_strings(file_path, min_length=4)

    return metadata