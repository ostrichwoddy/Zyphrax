# Zyphrax

A lightweight command-line malware analysis tool that performs static file inspection, heuristic risk scoring, optional VirusTotal scanning, and PDF report generation.

This tool is designed for educational, research, and defensive security use cases.

---

## Features

### Static File Analysis
Extracts and analyzes file metadata, including:

- Filename
- File size and type
- Entropy calculation
- Executable detection
- Extracted strings

---

### Heuristic Risk Scoring

The tool applies rule-based heuristics to estimate file risk:

- **High entropy detection** (possible packing/encryption)
- **Executable masquerading** (wrong or misleading extensions)
- **Suspicious filenames** (e.g., `payload`, `backdoor`, `exploit`)
- **Malware string patterns** (e.g., `/bin/sh`, `execve`, `cmd.exe`, `socket`)

Each indicator contributes to a risk score that determines the final verdict.

---

### Verdict System

| Score | Verdict |
|------|--------|
| 0–2  | Probably Safe |
| 3–5  | Suspicious |
| 6+   | Malware |

---

### VirusTotal Integration (Optional)

If enabled, the tool can:

- Submit files or hashes to VirusTotal
- Retrieve scan results
- Display detection summary and verdict

---

### PDF Report Generation

Generates a structured PDF report containing:

- File metadata
- Heuristic analysis results
- Risk score and verdict
- Extracted strings
- VirusTotal results (if enabled)

---

## Project Structure

```text
.
├── analyzer.py        # Main CLI application
├── metadata.py        # File metadata + string extraction
├── vt_scan.py         # VirusTotal API integration
└── report.pdf         # Generated output (optional)
```
## Contributing

Contributions are welcome! This project is a learning-focused malware analysis tool, and any improvements are appreciated.

### Ways to contribute

You can help by:

- Improving heuristic detection rules  
- Adding support for PE/ELF binary analysis  
- Enhancing string extraction accuracy  
- Expanding VirusTotal integration features  
- Improving PDF report formatting and readability  
- Fixing bugs or improving performance  
- Adding unit tests or test samples  
- Improving CLI help messages and usability  

---

### Getting started

1. Fork the repository  
2. Clone your fork:
```b
git clone https://github.com/your-username/repo-name.git
```
3. Create a new branch:
```
git checkout -b feature-name
```
4. Make your changes
5. Test your changes locally
6. Commit your changes:
```
git commit -m "Describe your change"
```
7. Push to your fork:
```
git push origin feature-name
```
8. Open a Pull Request

### Reporting issues
If you find a bug or want to request a feature, please open an issue including:

- Clear description of the problem
- Steps to reproduce it
- Expected vs actual behavior
- Relevant logs or sample inputs (if possible)

### Note
This project is intended for educational and defensive security purposes only. Contributions must follow ethical and legal usage.