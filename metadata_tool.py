#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import subprocess
import hashlib
import mimetypes
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

# ---------- Helpers ----------

def check_exiftool(exiftool_path: str = "exiftool") -> None:
    """Ensure exiftool is available."""
    try:
        subprocess.run([exiftool_path, "-ver"], capture_output=True, text=True, check=True)
    except FileNotFoundError:
        print("[!] exiftool is not installed. Install on Kali/Debian:\n    sudo apt update && sudo apt install exiftool -y")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[!] exiftool error: {e}")
        sys.exit(1)

def human_size(num: int) -> str:
    for unit in ["B","KB","MB","GB","TB"]:
        if num < 1024.0:
            return f"{num:.2f} {unit}"
        num /= 1024.0
    return f"{num:.2f} PB"

def file_hashes(path: str, algos: List[str]) -> Dict[str, str]:
    hash_objs = {}
    for algo in algos:
        try:
            hash_objs[algo] = hashlib.new(algo)
        except ValueError:
            print(f"[!] Unknown hash algorithm '{algo}', skipping.")
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            for h in hash_objs.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hash_objs.items()}

def file_stat(path: str) -> Dict[str, Any]:
    st = os.stat(path, follow_symlinks=False)
    info = {
        "size_bytes": st.st_size,
        "size_human": human_size(st.st_size),
        "permissions_octal": oct(st.st_mode & 0o777),
        "inode": getattr(st, "st_ino", None),
        "device": getattr(st, "st_dev", None),
        "uid": getattr(st, "st_uid", None),
        "gid": getattr(st, "st_gid", None),
        "atime": datetime.fromtimestamp(st.st_atime).isoformat(),
        "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
        "ctime": datetime.fromtimestamp(st.st_ctime).isoformat(),
    }
    # Try to resolve owner/group names on Linux
    try:
        import pwd, grp  # type: ignore
        if info["uid"] is not None:
            info["owner"] = pwd.getpwuid(info["uid"]).pw_name
        if info["gid"] is not None:
            info["group"] = grp.getgrgid(info["gid"]).gr_name
    except Exception:
        pass
    mime, enc = mimetypes.guess_type(path)
    info["mime_type"] = mime
    info["encoding"] = enc
    return info

def exiftool_metadata(path: str, exiftool_path: str = "exiftool") -> Dict[str, Any]:
    """
    Get metadata via exiftool. We favor JSON (-j) for structured output.
    If exiftool can't parse, we still capture any stdout.
    """
    try:
        # -j for JSON; -ignoreMinorErrors to be resilient
        result = subprocess.run(
            [exiftool_path, "-ignoreMinorErrors", "-j", path],
            capture_output=True, text=True, check=True
        )
        data = json.loads(result.stdout)
        if isinstance(data, list) and data:
            return data[0]
        return {"raw_exiftool_output": result.stdout.strip()}
    except subprocess.CalledProcessError as e:
        return {"exiftool_error": str(e), "stderr": e.stderr}
    except json.JSONDecodeError:
        # Fallback to plain text
        try:
            txt = subprocess.run([exiftool_path, path], capture_output=True, text=True, check=True).stdout
            return {"raw_exiftool_output": txt.strip()}
        except Exception as e:
            return {"exiftool_error": str(e)}

def collect_targets(inputs: List[str], recursive: bool) -> List[str]:
    files: List[str] = []
    for p in inputs:
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            if recursive:
                for root, _, fnames in os.walk(p):
                    for fn in fnames:
                        fpath = os.path.join(root, fn)
                        if os.path.isfile(fpath):
                            files.append(fpath)
            else:
                # Non-recursive: only direct children files
                for fn in os.listdir(p):
                    fpath = os.path.join(p, fn)
                    if os.path.isfile(fpath):
                        files.append(fpath)
        else:
            print(f"[!] Skipping non-existent path: {p}")
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for f in files:
        if f not in seen:
            unique.append(f)
            seen.add(f)
    return unique

# ---------- Renderers ----------

def render_txt(results: List[Dict[str, Any]]) -> str:
    lines = []
    banner = "Kali Metadata Tool — Detailed Report"
    lines.append(banner)
    lines.append("=" * len(banner))
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    for r in results:
        lines.append("-" * 80)
        lines.append(f"File: {r['path']}")
        lines.append("-" * 80)
        fi = r.get("file_info", {})
        lines.append(f" Size: {fi.get('size_human')} ({fi.get('size_bytes')} bytes)")
        lines.append(f" MIME: {fi.get('mime_type')}")
        lines.append(f" Permissions: {fi.get('permissions_octal')}")
        owner = fi.get("owner") or fi.get("uid")
        group = fi.get("group") or fi.get("gid")
        lines.append(f" Owner/Group: {owner}:{group}")
        lines.append(f" Times: atime={fi.get('atime')} mtime={fi.get('mtime')} ctime={fi.get('ctime')}")
        hashes = r.get("hashes", {})
        if hashes:
            lines.append(" Hashes:")
            for algo, val in hashes.items():
                lines.append(f"  - {algo.upper()}: {val}")
        meta = r.get("metadata", {})
        lines.append(" Metadata (exiftool):")
        if "raw_exiftool_output" in meta:
            lines.append(meta["raw_exiftool_output"])
        else:
            # Pretty print key/values (flat only)
            for k, v in meta.items():
                try:
                    if isinstance(v, (dict, list)):
                        v = json.dumps(v, ensure_ascii=False)
                    lines.append(f"  {k}: {v}")
                except Exception:
                    lines.append(f"  {k}: {v}")
        lines.append("")
    return "\n".join(lines)

def render_json(results: List[Dict[str, Any]]) -> str:
    return json.dumps({"generated_at": datetime.now().isoformat(), "items": results}, ensure_ascii=False, indent=2)

def render_html(results: List[Dict[str, Any]]) -> str:
    head = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kali Metadata Tool — Report</title>
<style>
body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Arial, sans-serif; margin: 24px; }}
h1 {{ font-size: 1.6rem; margin-bottom: 0.25rem; }}
h2 {{ font-size: 1.1rem; margin-top: 1.2rem; }}
.card {{ border: 1px solid #ddd; border-radius: 12px; padding: 16px; margin: 12px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }}
.kv {{ display: grid; grid-template-columns: 180px 1fr; gap: 6px 12px; }}
.kv div.label {{ color: #555; }}
pre {{ white-space: pre-wrap; word-wrap: break-word; background: #fafafa; border: 1px dashed #ddd; padding: 12px; border-radius: 8px; }}
small {{ color: #666; }}
.hashes code {{ word-break: break-all; }}
footer {{ margin-top: 24px; font-size: 0.9rem; color: #666; }}
</style>
</head><body>
<h1>Kali Metadata Tool — Detailed Report</h1>
<small>Generated at {datetime.now().isoformat()}</small>
"""
    body = []
    for r in results:
        fi = r.get("file_info", {})
        meta = r.get("metadata", {})
        hashes = r.get("hashes", {})
        body.append('<div class="card">')
        body.append(f"<h2>{r['path']}</h2>")
        body.append('<div class="kv">')
        def row(label, value):
            body.append(f'<div class="label"><b>{label}</b></div><div>{value}</div>')
        row("Size", f"{fi.get('size_human')} ({fi.get('size_bytes')} bytes)")
        row("MIME", fi.get("mime_type"))
        row("Permissions", fi.get("permissions_octal"))
        row("Owner", fi.get("owner") or fi.get("uid"))
        row("Group", fi.get("group") or fi.get("gid"))
        row("Access Time", fi.get("atime"))
        row("Modify Time", fi.get("mtime"))
        row("Change Time", fi.get("ctime"))
        body.append("</div>")
        if hashes:
            body.append('<h3>Hashes</h3><div class="hashes">')
            for algo, val in hashes.items():
                body.append(f"<div><b>{algo.upper()}</b>: <code>{val}</code></div>")
            body.append("</div>")
        body.append("<h3>Metadata (exiftool)</h3>")
        if "raw_exiftool_output" in meta:
            body.append(f"<pre>{meta['raw_exiftool_output']}</pre>")
        else:
            pretty = json.dumps(meta, ensure_ascii=False, indent=2)
            body.append(f"<pre>{pretty}</pre>")
        body.append("</div>")
    foot = "<footer>Generated by kali-metadata-tool</footer></body></html>"
    return head + "\n".join(body) + foot

# ---------- Main ----------

def run(paths: List[str], recursive: bool, format_: str, output: Optional[str],
        hashes: List[str], exiftool_path: str, quiet: bool) -> int:
    check_exiftool(exiftool_path)
    targets = collect_targets(paths, recursive)
    if not targets:
        print("[!] No files found.")
        return 2
    results: List[Dict[str, Any]] = []
    for idx, path in enumerate(targets, 1):
        if not quiet:
            print(f"[+] Processing ({idx}/{len(targets)}): {path}")
        try:
            item: Dict[str, Any] = {
                "path": os.path.abspath(path),
                "file_info": file_stat(path),
                "hashes": file_hashes(path, hashes) if hashes else {},
                "metadata": exiftool_metadata(path, exiftool_path)
            }
            results.append(item)
        except Exception as e:
            results.append({"path": os.path.abspath(path), "error": str(e)})

    # Render
    if format_ == "txt":
        rendered = render_txt(results)
        ext = ".txt"
    elif format_ == "json":
        rendered = render_json(results)
        ext = ".json"
    elif format_ == "html":
        rendered = render_html(results)
        ext = ".html"
    else:
        print(f"[!] Unknown format: {format_}")
        return 3

    # Output
    if output:
        # If output is a directory, write timestamped report inside it
        if os.path.isdir(output):
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            outfile = os.path.join(output, f"metadata-report-{ts}{ext}")
        else:
            # If parent dir doesn't exist, try to create
            parent = os.path.dirname(os.path.abspath(output)) or "."
            os.makedirs(parent, exist_ok=True)
            # Use provided path as file path; if no extension, add one
            outfile = output if output.endswith(ext) else output + ext
        with open(outfile, "w", encoding="utf-8") as f:
            f.write(rendered)
        if not quiet:
            print(f"[✓] Report written to: {outfile}")
    else:
        print(rendered)
    return 0

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="metadata_tool",
        description="Extract rich file metadata on Kali Linux using exiftool + filesystem details + hashes."
    )
    p.add_argument("paths", nargs="+", help="Files and/or directories to analyze")
    p.add_argument("-r", "--recursive", action="store_true", help="Recurse into directories")
    p.add_argument("-f", "--format", dest="format_", choices=["txt", "json", "html"], default="txt",
                   help="Report format (default: txt)")
    p.add_argument("-o", "--output", help="Write report to file or directory; print to stdout if omitted")
    p.add_argument("--hashes", default="md5,sha256",
                   help="Comma-separated hash algorithms (e.g., md5,sha1,sha256). Use '' to disable")
    p.add_argument("--exiftool-path", default="exiftool", help="Path to exiftool binary")
    p.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (less console output)")
    return p.parse_args(argv)

def main() -> None:
    ns = parse_args(sys.argv[1:])
    hashes = [h.strip().lower() for h in ns.hashes.split(",") if h.strip()] if ns.hashes is not None else []
    code = run(
        paths=ns.paths,
        recursive=ns.recursive,
        format_=ns.format_,
        output=ns.output,
        hashes=hashes,
        exiftool_path=ns.exiftool_path,
        quiet=ns.quiet
    )
    sys.exit(code)

if __name__ == "__main__":
    main()
