# ALDS (Anti-Leak Document Sanitizer)

High-performance desktop application built with C++ and native Win32 API for batch metadata removal, revision cleaning, and cryptographic hash randomization across office documents and PDF files.

---

### Features
<img width="954" height="663" alt="image" src="https://github.com/user-attachments/assets/7e583db5-8c15-47b4-9a0f-419f9fb43e2a" />

* **Supported Formats:**
  * **PDF:** Strips Author, Producer, Creator metadata, creation/modification timestamps, and raw XML XMP packet streams.
  * **DOCX / XLSX / PPTX:** Cleans core document properties, custom application properties, author traces, template paths, revision history, and hidden comments.
* **Hash Randomization:**
  * Appends non-breaking trailing structural tokens to modify MD5, SHA-1, and SHA-256 file hashes without corrupting document integrity.
* **Interface & UX:**
  * Native Win32 Drag & Drop support for individual files and whole directories.
  * Asynchronous multi-threaded processing for an ultra-responsive, non-blocking UI.
  * Real-time file status tracking, error validation, and activity logs.
  * Automatic output directory generation (`sanitized_output/`).

---
[Downloads ALDS v2.0.0](https://github.com/eloyssync/ALDS/releases/tag/v2.0.0)

### Requirements

* Windows 10 / 11 (x64)
* C++20 compatible compiler (MSVC / Clang / GCC)

---

### Build & Run

1. **Clone the repository:**
```bash
git clone https://github.com/eloyssync/ALDS.git
cd ALDS
Compile:

Open ALDS.sln in Visual Studio 2022.

Set configuration to Release | x64.

Build Solution (Build -> Build Solution or Ctrl + Shift + B).

The compiled binary will be located in the x64/Release/ directory.

License
Distributed under the MIT License. See LICENSE for more information.
