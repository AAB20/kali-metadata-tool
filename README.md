# Kali Metadata Tool

A fast, scriptable CLI to extract **rich file metadata** on Kali Linux:
- Filesystem details (size, MIME, permissions, owner/group, times)
- **Cryptographic hashes** (MD5, SHA1, SHA256 …)
- **Full EXIF/metadata** via `exiftool`
- Report output as **TXT, JSON, or HTML**
- Works on single files or **directories (recursive)**

> “What gets measured gets managed.” — Peter Drucker

---

## ✨ Features
- ✅ Structured JSON for automation
- ✅ Clean HTML report for sharing
- ✅ Human-readable TXT for terminals
- ✅ Handles large trees with `--recursive`
- ✅ Choose hash algorithms with `--hashes`

---

## 🔧 Requirements
- **Kali/Debian** packages:
  ```bash
  sudo apt update && sudo apt install exiftool -y


# Clone
git clone https://github.com/<your-username>/kali-metadata-tool.git
cd kali-metadata-tool

# Make executable
chmod +x metadata_tool.py

# Single file → TXT to stdout
./metadata_tool.py /path/to/file.jpg

# Directory recursively → HTML report saved
./metadata_tool.py /path/to/folder -r -f html -o reports/

# JSON for automation → redirected to file
./metadata_tool.py sample.png -f json -o report.json

# Custom hashes
./metadata_tool.py sample.png --hashes md5,sha1,sha256

# Quiet mode (less logs)
./metadata_tool.py /path/to/folder -r -f txt -o report.txt -q
