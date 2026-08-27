# ALDS (Anti-Leak Document Sanitizer)

Desktop application built with Python and PyQt6 for batch metadata removal, revision cleaning, and cryptographic hash randomization across office documents and PDF files.

> **Note on Antivirus Detections:** Standalone Windows executables built with packaging tools may trigger false positives on some antivirus engines. The project is 100% open source.

---

### Features

* **Supported Formats:**
  * **PDF:** Strips Author, Producer, Creator metadata, creation/modification timestamps, and raw XML XMP packet streams.
  * **DOCX / XLSX / PPTX:** Cleans core document properties, custom application properties, author traces, template paths, revision history, and hidden comments.
* **Hash Randomization:**
  * Appends non-breaking trailing structural tokens to modify MD5, SHA-1, and SHA-256 file hashes without corrupting document integrity.
* **Interface & UX:**
  * Drag and drop support for individual files and whole directories.
  * Multi-threaded processing (`QThread`) for a responsive, non-blocking UI.
  * Real-time file status tracking, error validation, and activity logs.
  * Automatic output directory generation (`sanitized_output/`).

---

### Requirements

* Python 3.10 or higher
* PyQt6
* pypdf, python-docx, openpyxl, python-pptx

---

### Installation & Run

1. Clone the repository:
```bash
git clone https://github.com/eloyssync/ALDS.git
cd ALDS
Install dependencies:

Bash
pip install -r requirements.txt
Run the application:

Bash
python doc_sanitizer.py
(Or run start.bat on Windows)

License
Distributed under the MIT License. See LICENSE for more information.