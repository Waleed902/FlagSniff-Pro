"""Forensics: file carving and transfer extraction helpers.

This module centralizes carving logic previously embedded in monolithic analyzers.
Functions are defensive and side-effect free. They accept simple inputs (streams,
packets, raw bytes) and return plain dicts/lists to keep them reusable.
"""
from __future__ import annotations

from typing import Dict, Any, List, Optional, Tuple
import hashlib
import re

# Lightweight helpers

def looks_like_text(data: bytes, *, small_threshold: int = 1024) -> bool:
    try:
        text = data.decode('utf-8', errors='ignore')
        if not text:
            return False
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        ratio = printable / max(1, len(text))
        threshold = 0.6 if len(data) < small_threshold else 0.7
        return ratio > threshold
    except Exception:
        return False


def is_likely_file_data(data: bytes) -> bool:
    if not data or len(data) < 5:
        return False
    if len(data) < 2048:  # be permissive for small items
        return True

    signatures = [
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff",
        b"GIF87a",
        b"GIF89a",
        b"%PDF-",
        b"PK\x03\x04",
        b"RIFF",
        b"ftyp",
        b"\x00\x00\x00\x20ftyp",
    ]
    if any(data.startswith(sig) for sig in signatures):
        return True

    try:
        sample = data[:2000]
        text = sample.decode('utf-8', errors='ignore')
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        if text and printable / len(text) > 0.7:
            return True
    except Exception:
        pass

    if len(data) > 50:
        return len(set(data[:500])) > 3

    return True


def determine_file_type_from_data(data: bytes, ext: str) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG Image"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG Image"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "GIF Image"
    if data.startswith(b"%PDF-"):
        return "PDF Document"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP Archive"
    if data.startswith(b"RIFF"):
        return "RIFF Container"
    if b"ftyp" in data[:32]:
        return "MP4 Video"

    ext_map = {
        'jpg': 'JPEG Image', 'jpeg': 'JPEG Image', 'png': 'PNG Image', 'gif': 'GIF Image',
        'pdf': 'PDF Document', 'txt': 'Text File', 'html': 'HTML Document',
        'zip': 'ZIP Archive', 'rar': 'RAR Archive', '7z': '7-Zip Archive',
        'mp4': 'MP4 Video', 'avi': 'AVI Video', 'mov': 'QuickTime Video',
        'mp3': 'MP3 Audio', 'wav': 'WAV Audio', 'ogg': 'OGG Audio',
        'doc': 'Word Document', 'docx': 'Word Document', 'xls': 'Excel Spreadsheet',
        'dat': 'Data File', 'log': 'Log File', 'cfg': 'Configuration File'
    }
    if ext and ext.lower() in ext_map:
        return ext_map[ext.lower()]

    # small payload heuristics
    if len(data) < 2048:
        try:
            text = data.decode('utf-8', errors='ignore')
            ratio = sum(1 for c in text if c.isprintable() or c in '\n\r\t') / max(1, len(text))
            if ratio > 0.8:
                return 'Text File'
            if ratio > 0.5:
                return 'Data File'
            return 'Binary File'
        except Exception:
            return 'Binary File'

    try:
        text = data[:1000].decode('utf-8', errors='ignore')
        ratio = sum(1 for c in text if c.isprintable() or c in '\n\r\t') / max(1, len(text))
        if ratio > 0.8:
            return 'Text File'
    except Exception:
        pass
    return 'Binary File'


# Extraction primitives

def extract_archive_data(data: bytes, pos: int, file_info: Dict[str, Any]) -> bytes:
    try:
        ext = (file_info.get('ext') or '').lower()
        if ext == 'zip':
            import io, zipfile
            buf = io.BytesIO(data[pos:])
            with zipfile.ZipFile(buf, 'r') as zf:
                zf.testzip()
                total = 0
                for info in zf.infolist():
                    total += info.compress_size + 100
                extract_size = min(total + 1024, len(data) - pos, 50 * 1024 * 1024)
                return data[pos:pos + extract_size]
        if ext == 'gz':
            import io, gzip
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(data[pos:])) as gz:
                    _ = gz.read(1024)
                return data[pos:pos + min(2 * 1024 * 1024, len(data) - pos)]
            except Exception:
                return data[pos:pos + min(2 * 1024 * 1024, len(data) - pos)]
        # default for other archives
        return data[pos:pos + min(5 * 1024 * 1024, len(data) - pos)]
    except Exception:
        return data[pos:pos + min(2 * 1024 * 1024, len(data) - pos)]


def extract_file_with_boundaries(data: bytes, pos: int, file_info: Dict[str, Any]) -> bytes:
    try:
        ext = (file_info.get('ext') or '').lower()
        end_marker = file_info.get('end_marker')

        if ext in ['png', 'jpg', 'gif', 'pdf']:
            if end_marker:
                search_limit = min(pos + 50 * 1024 * 1024, len(data))
                end_pos = data.find(end_marker, pos, search_limit)
                if end_pos != -1:
                    return data[pos:end_pos + len(end_marker)]
                return data[pos:pos + min(10 * 1024 * 1024, len(data) - pos)]
            return data[pos:pos + min(5 * 1024 * 1024, len(data) - pos)]

        if ext in ['zip', 'gz', 'bz2', '7z', 'rar']:
            return extract_archive_data(data, pos, file_info)

        if ext in ['exe', 'elf']:
            return data[pos:pos + min(20 * 1024 * 1024, len(data) - pos)]

        if ext == 'txt' and 'CTF' in (file_info.get('name') or ''):
            end_pos = data.find(b'}', pos)
            if end_pos != -1:
                return data[pos:end_pos + 1]
            return data[pos:pos + min(1024, len(data) - pos)]

        return data[pos:pos + min(2 * 1024 * 1024, len(data) - pos)]
    except Exception:
        return data[pos:pos + min(1024 * 1024, len(data) - pos)]


# High-level carving / extraction

def enhanced_file_carving(streams: Dict[str, Any], file_signatures: Dict[bytes, Dict[str, Any]]) -> List[Dict[str, Any]]:
    carved: List[Dict[str, Any]] = []
    if not streams:
        return carved

    # extended signatures layered on top of provided
    extended_signatures = {
        b'\x89PNG\r\n\x1a\n': {'ext': 'png', 'name': 'PNG Image', 'end_marker': b'\x00\x00\x00\x00IEND\xaeB`\x82'},
        b'\xff\xd8\xff': {'ext': 'jpg', 'name': 'JPEG Image', 'end_marker': b'\xff\xd9'},
        b'GIF87a': {'ext': 'gif', 'name': 'GIF Image', 'end_marker': b'\x00\x3b'},
        b'GIF89a': {'ext': 'gif', 'name': 'GIF Image', 'end_marker': b'\x00\x3b'},
        b'RIFF': {'ext': 'webp', 'name': 'WebP Image', 'end_marker': b'WEBP'},
        b'%PDF': {'ext': 'pdf', 'name': 'PDF Document', 'end_marker': b'%%EOF'},
        b'PK\x03\x04': {'ext': 'zip', 'name': 'ZIP Archive', 'end_marker': None},
        b'\x1f\x8b\x08': {'ext': 'gz', 'name': 'GZIP Archive', 'end_marker': None},
        b'BZh': {'ext': 'bz2', 'name': 'BZIP2 Archive', 'end_marker': None},
    b'\x37\x7a\xbc\xaf\x27\x1c': {'ext': '7z', 'name': '7-Zip Archive', 'end_marker': None},
        b'\x52\x61\x72\x21\x1a\x07': {'ext': 'rar', 'name': 'RAR Archive', 'end_marker': None},
        b'FLAG{': {'ext': 'txt', 'name': 'CTF Flag File', 'end_marker': b'}'},
        b'CTF{': {'ext': 'txt', 'name': 'CTF Flag File', 'end_marker': b'}'},
        b'PICOCTF{': {'ext': 'txt', 'name': 'PicoCTF Flag File', 'end_marker': b'}'},
    }
    all_sigs: Dict[bytes, Dict[str, Any]] = {}
    all_sigs.update(file_signatures or {})
    all_sigs.update(extended_signatures)

    for stream_id, stream in (streams.items() if isinstance(streams, dict) else []):
        data = stream.get('data', b'') if isinstance(stream, dict) else b''
        if not data:
            continue
        for sig, info in all_sigs.items():
            start = 0
            while True:
                pos = data.find(sig, start)
                if pos == -1:
                    break
                blob = extract_file_with_boundaries(data, pos, info)
                if blob:
                    md5 = hashlib.md5(blob).hexdigest()
                    carved.append({
                        'stream_id': stream_id,
                        'file_type': info.get('name') or 'Unknown',
                        'extension': info.get('ext') or 'bin',
                        'size': len(blob),
                        'md5_hash': md5,
                        'position': pos,
                        'data': blob,
                        'filename': f"carved_{md5[:8]}.{info.get('ext','bin')}",
                        'source_protocol': stream.get('protocol', 'Unknown'),
                        'source_ips': [stream.get('src_ip'), stream.get('dst_ip')],
                        'actual_name': f"{info.get('name','file')}.{info.get('ext','bin')}",
                        'carving_method': 'enhanced'
                    })
                start = pos + max(1, len(sig))
    return carved


def extract_ftp_files(streams: Dict[str, Any]) -> List[Dict[str, Any]]:
    ftp_files: List[Dict[str, Any]] = []
    if not streams:
        return ftp_files

    ftp_cmds: Dict[str, Dict[str, Any]] = {}
    for sid, s in streams.items():
        data = s.get('data', b'') if isinstance(s, dict) else b''
        if not data:
            continue
        try:
            text = data.decode('utf-8', errors='ignore')
            for line in text.split('\n'):
                line = line.strip()
                if line.startswith('RETR '):
                    filename = line[5:].strip()
                    if filename.startswith('/'):
                        filename = filename[1:]
                    ftp_cmds[sid] = {
                        'filename': filename,
                        'stream_id': sid,
                        'src_ip': s.get('src_ip'),
                        'dst_ip': s.get('dst_ip'),
                        'src_port': s.get('src_port'),
                        'dst_port': s.get('dst_port'),
                    }
                    break
        except Exception:
            continue

    for sid, s in streams.items():
        data = s.get('data', b'') if isinstance(s, dict) else b''
        if not data or len(data) < 5:
            continue
        try:
            text_sample = data[:500].decode('utf-8', errors='ignore')
            ftp_markers = ['USER ', 'PASS ', 'RETR ', 'LIST ', 'PASV', 'STOR ', 'QUIT', '220 ', '331 ', '230 ', '226 ', '221 ', '150 ', '425 ', '227 ']
            if any(m in text_sample for m in ftp_markers):
                continue
        except Exception:
            pass

        if len(data) < 2048 or is_likely_file_data(data):
            src_ip, dst_ip = s.get('src_ip'), s.get('dst_ip')
            src_port, dst_port = s.get('src_port'), s.get('dst_port')
            for cmd_sid, cmd in list(ftp_cmds.items()):
                ip_match = ((cmd['src_ip'] == src_ip and cmd['dst_ip'] == dst_ip) or (cmd['src_ip'] == dst_ip and cmd['dst_ip'] == src_ip))
                port_diff = (src_port != 21 and dst_port != 21 and src_port != cmd.get('src_port') and dst_port != cmd.get('dst_port'))
                if ip_match and (port_diff or len(data) > 100):
                    filename = cmd['filename']
                    md5 = hashlib.md5(data).hexdigest()
                    ext = ''
                    actual_name = filename
                    if '.' in filename:
                        ext = filename.split('.')[-1].lower()
                    else:
                        ext = 'txt' if looks_like_text(data) else 'dat'
                        actual_name = f"{filename}.{ext}"
                    file_type = determine_file_type_from_data(data, ext)
                    ftp_files.append({
                        'stream_id': sid,
                        'file_type': file_type,
                        'extension': ext,
                        'size': len(data),
                        'md5_hash': md5,
                        'position': 0,
                        'data': data,
                        'filename': f"ftp_{md5[:8]}.{ext}" if ext else f"ftp_{md5[:8]}",
                        'source_protocol': 'FTP',
                        'source_ips': [src_ip, dst_ip],
                        'actual_name': actual_name,
                        'ftp_command': f"RETR {cmd['filename']}",
                        'original_name': cmd['filename'],
                    })
                    del ftp_cmds[cmd_sid]
                    break
    return ftp_files


def extract_http_files(packets: List[Any]) -> List[Dict[str, Any]]:
    http_files: List[Dict[str, Any]] = []
    try:
        from scapy.all import TCP, IP, Raw  # type: ignore
        http_sessions: Dict[str, Dict[str, Any]] = {}
        for i, pkt in enumerate(packets or []):
            try:
                if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
                    continue
                ip, tcp = pkt[IP], pkt[TCP]
                if tcp.dport in [80, 443, 8080, 8443] or tcp.sport in [80, 443, 8080, 8443]:
                    key = f"{ip.src}:{tcp.sport}-{ip.dst}:{tcp.dport}"
                    s = http_sessions.setdefault(key, {
                        'packets': [], 'src_ip': ip.src, 'dst_ip': ip.dst, 'src_port': tcp.sport, 'dst_port': tcp.dport
                    })
                    s['packets'].append((i, pkt))
            except Exception:
                continue

        for key, s in http_sessions.items():
            stream = b''
            for idx, pkt in s['packets']:
                try:
                    if pkt.haslayer(Raw):
                        stream += pkt[Raw].load
                except Exception:
                    continue
            if not stream:
                continue
            try:
                parts = stream.split(b'HTTP/1.')
                for resp in parts[1:]:
                    ct_m = re.search(rb'Content-Type:\s*([^\r\n]+)', resp, re.IGNORECASE)
                    if not ct_m:
                        continue
                    content_type = ct_m.group(1).decode('utf-8', errors='ignore').strip()
                    header_end = resp.find(b'\r\n\r\n')
                    if header_end == -1:
                        continue
                    body = resp[header_end + 4:]
                    if not body:
                        continue
                    if len(body) > 50 * 1024 * 1024:
                        body = body[:50 * 1024 * 1024]
                    ext = 'bin'
                    ftype = 'Binary File'
                    if 'image/' in content_type:
                        ext = content_type.split('/')[-1].split('+')[0]
                        if ext == 'jpeg':
                            ext = 'jpg'
                        ftype = f"{ext.upper()} Image"
                    elif 'application/pdf' in content_type:
                        ext, ftype = 'pdf', 'PDF Document'
                    elif 'application/zip' in content_type:
                        ext, ftype = 'zip', 'ZIP Archive'
                    elif 'text/' in content_type:
                        ext, ftype = 'txt', 'Text File'
                    md5 = hashlib.md5(body).hexdigest()
                    http_files.append({
                        'stream_id': key,
                        'file_type': ftype,
                        'extension': ext,
                        'size': len(body),
                        'md5_hash': md5,
                        'position': 0,
                        'data': body,
                        'filename': f"http_{md5[:8]}.{ext}",
                        'source_protocol': 'HTTP',
                        'source_ips': [s['src_ip'], s['dst_ip']],
                        'actual_name': f"downloaded_file.{ext}",
                        'carving_method': 'http_transfer',
                        'content_type': content_type
                    })
            except Exception:
                continue
    except Exception:
        pass
    return http_files


def carve_files_from_streams(streams: Dict[str, Any], file_signatures: Dict[bytes, Dict[str, Any]]) -> List[Dict[str, Any]]:
    carved: List[Dict[str, Any]] = []
    if not streams:
        return carved
    for stream_id, stream in (streams.items() if isinstance(streams, dict) else []):
        data = stream.get('data', b'') if isinstance(stream, dict) else b''
        if not data:
            continue
        for sig, info in (file_signatures or {}).items():
            start = 0
            while True:
                pos = data.find(sig, start)
                if pos == -1:
                    break
                # conservative 1MB slice
                frag = data[pos:pos + min(1024 * 1024, len(data) - pos)]
                md5 = hashlib.md5(frag).hexdigest()
                carved.append({
                    'stream_id': stream_id,
                    'file_type': info.get('name', ''),
                    'extension': info.get('ext', 'bin'),
                    'size': len(frag),
                    'md5_hash': md5,
                    'position': pos,
                    'data': frag,
                    'filename': f"carved_{md5[:8]}.{info.get('ext','bin')}",
                    'source_protocol': stream.get('protocol', 'Unknown'),
                    'source_ips': [stream.get('src_ip'), stream.get('dst_ip')],
                    'actual_name': f"{info.get('name','file')}.{info.get('ext','bin')}"
                })
                start = pos + len(sig)
    return carved
