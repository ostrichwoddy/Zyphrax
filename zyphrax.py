import argparse
from vt_scan import scanfile
from metadata import get_file_metadata
import re
from reportlab.lib.pagesizes import LETTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

# ----------------- Malware Analysis -----------------
def analyze_metadata(metadata):
    score = 0
    reasoning = []

    # 1. High entropy
    entropy = metadata.get("entropy", 0)
    if entropy > 7.5:
        score += 3
        reasoning.append(f"High entropy ({entropy:.2f})")

    # 2. Executable masquerade
    common_exec_exts = {".exe", ".bin", ".sh", ".bat", ".cmd", ".elf", ".py"}
    apparent_ext = metadata.get("apparent_extension", "").lower()
    is_exec = metadata.get("executable", False)
    if is_exec and apparent_ext not in common_exec_exts:
        score += 2
        reasoning.append(f"Executable masquerade (extension: {apparent_ext})")

    # 3. Suspicious filename
    suspicious_keywords = ["revshell", "hack", "payload", "malware", "backdoor", "exploit"]
    filename = metadata.get("filename", "").lower()
    if any(keyword in filename for keyword in suspicious_keywords):
        score += 2
        reasoning.append(f"Suspicious filename ({filename})")

    # 4. Suspicious strings
    suspicious_patterns = [
        r"/bin/sh", r"socket", r"execve", r"connect", r"dup2", r"system", r"wget", r"curl",
        r"inet_addr", r"htons", r"bash", r"nc", r"cmd.exe"
    ]
    strings = metadata.get("strings", [])
    matches = sum(any(re.search(pattern, s, re.IGNORECASE) for pattern in suspicious_patterns) for s in strings)
    if matches > 0:
        score += min(matches, 5)
        reasoning.append(f"Suspicious strings detected ({matches})")

    # Verdict
    if score >= 6:
        verdict = "Malware"
    elif score >= 3:
        verdict = "Suspicious"
    else:
        verdict = "Probably Safe"

    return {"Score": score, "Verdict": verdict, "Reasoning": reasoning}


# ----------------- PDF Report -----------------
def generate_pdf_report(filename, metadata, metadata_analysis, strings_output=None, vt_results=None):
    doc = SimpleDocTemplate(filename, pagesize=LETTER,
                            rightMargin=0.75*inch, leftMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)
    elements = []
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Heading1Center', parent=styles['Heading1'], alignment=1, spaceAfter=12))
    styles.add(ParagraphStyle(name='Mono', fontName='Courier', fontSize=8, leading=10))
    value_style = ParagraphStyle(
        'ValueStyle',
        parent=styles['Normal'],
        fontSize=8,
        leading=10,
        wordWrap='CJK'  # forces wrapping for long text
    )

    # ----------------- Title -----------------
    elements.append(Paragraph("Malware Analysis Report", styles['Heading1Center']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"<b>File:</b> {metadata.get('filename', 'Unknown')}", styles['Normal']))
    elements.append(Spacer(1, 12))

    # ----------------- File Metadata Table -----------------
    elements.append(Paragraph("<b>File Metadata</b>", styles['Heading2']))
    data = []
    for key, value in metadata.items():
        if key == "strings":
            value = f"{len(value)} strings"
        data.append([key.replace('_', ' ').capitalize(), Paragraph(str(value), value_style)])
    table = Table(data, colWidths=[2*inch, 4*inch], repeatRows=0)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
        ('ALIGN',(0,0),(-1,-1),'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.black),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 12))

    # ----------------- Metadata Analysis -----------------
    elements.append(Paragraph("<b>Metadata Analysis</b>", styles['Heading2']))
    verdict_color = colors.green if metadata_analysis["Verdict"] == "Probably Safe" \
                    else colors.orange if metadata_analysis["Verdict"] == "Suspicious" \
                    else colors.red
    elements.append(Paragraph(f"<b>Score:</b> {metadata_analysis['Score']}", styles['Normal']))
    elements.append(
        Paragraph(
            f"<b>Verdict:</b> <font color='{verdict_color.hexval()}'>{metadata_analysis['Verdict']}</font>",
            styles['Normal']
        )
    )
    elements.append(Spacer(1, 6))
    elements.append(Paragraph("<b>Reasoning:</b>", styles['Normal']))
    if metadata_analysis["Reasoning"]:
        for reason in metadata_analysis["Reasoning"]:
            elements.append(Paragraph(f"- {reason}", styles['Normal']))
    else:
        elements.append(Paragraph("Metadata analysis did not flag anything", styles['Normal']))
    elements.append(Spacer(1, 12))

    # ----------------- Strings Output -----------------
    if strings_output:
        elements.append(Paragraph("<b>Extracted Strings</b>", styles['Heading2']))
        for i, s in enumerate(strings_output):
            elements.append(Paragraph(s, styles['Mono']))
            if (i + 1) % 60 == 0:  # page break every 60 strings
                elements.append(PageBreak())
        elements.append(Spacer(1, 12))

    # ----------------- VirusTotal Output -----------------
    if vt_results:
        elements.append(Paragraph("<b>VirusTotal Scan Summary</b>", styles['Heading2']))
        # Verdict highlighted
        vt_verdict = vt_results.get("Verdict", "Unknown")
        vt_color = colors.green if vt_verdict.lower() == "clean" \
                   else colors.orange if vt_verdict.lower() == "suspicious" \
                   else colors.red
        elements.append(
            Paragraph(f"<b>Verdict:</b> <font color='{vt_color.hexval()}'>{vt_verdict}</font>", styles['Normal'])
        )
        elements.append(Spacer(1, 6))
        # Other VT details
        for key, value in vt_results.items():
            if key.lower() == "verdict":
                continue
            elements.append(Paragraph(f"<b>{key}:</b> {value}", styles['Normal']))
        elements.append(Spacer(1, 12))

    doc.build(elements)
    print(f"\nPDF report generated: {filename}")


# ----------------- CLI Arguments -----------------
parser = argparse.ArgumentParser(description="Analyze a file locally and optionally with VirusTotal")
parser.add_argument("file", help="Path to the file to analyze")
parser.add_argument("--vt", action="store_true", help="Perform VirusTotal scan")
parser.add_argument("--strings", action="store_true", help="Print extracted strings from file")
parser.add_argument("--pdf", help="Generate PDF report with given filename")
args = parser.parse_args()

file_path = args.file
metadata = get_file_metadata(file_path)

# ----------------- Print Metadata -----------------
print("\nFILE METADATA\n-------------")
for key, value in metadata.items():
    if key == "strings":
        print(f"Strings count: {len(value)}")
        continue
    print(f"{key.capitalize().replace('_', ' ')}: {value}")

# ----------------- Strings Output -----------------
if args.strings and metadata.get("strings"):
    print("\nSTRINGS OUTPUT\n-------------")
    for s in metadata["strings"]:
        print(s)

# ----------------- Metadata Analysis -----------------
metadata_verdict = analyze_metadata(metadata)
print("\nMETADATA ANALYSIS\n-------------")
for key, value in metadata_verdict.items():
    if key == "Reasoning" and len(value) == 0:
        value = "Metadata analysis did not flag anything"
    print(f"{key}: {value}")

# ----------------- VirusTotal Scan -----------------
vt_results = None
if args.vt:
    vt_results = scanfile(file_path)
    if vt_results:
        print("\nVIRUSTOTAL SCAN SUMMARY\n-------------")
        for key, value in vt_results.items():
            print(f"{key}: {value}")

# ----------------- Generate PDF -----------------
if args.pdf:
    generate_pdf_report(
        filename=args.pdf,
        metadata=metadata,
        metadata_analysis=metadata_verdict,
        strings_output=metadata["strings"] if args.strings else None,
        vt_results=vt_results
    )