#!/usr/bin/env python3
"""
DNS Rebinding Verification Tool
================================
Verifies whether a client has correctly pinned its IP after initial DNS resolution.

How it works:
  1. Spins up a fake DNS server you control.
  2. Spins up two HTTP servers:
       - "real"  server on REAL_IP   (first DNS answer)
       - "trap"  server on TRAP_IP   (all subsequent DNS answers)
  3. You point the client at your fake DNS server.
  4. Client resolves the domain → gets REAL_IP → connects fine.
  5. DNS now switches to TRAP_IP.
  6. Client makes another request — if it re-resolves, it hits the TRAP server.

Result:
  TRAP server receives a connection  →  client is NOT pinned  (FAIL)
  TRAP server receives no connection →  client IS pinned      (PASS)

Requirements:
  pip install dnslib

Usage:
  # Default: binds real=127.0.0.1, trap=127.0.0.2, DNS on 127.0.0.1:5300
  python verify_ip_pinning.py

  # Custom domain / IPs / ports
  python verify_ip_pinning.py \\
      --domain api.example.com \\
      --real-ip 127.0.0.1 --real-port 8080 \\
      --trap-ip 127.0.0.2 --trap-port 8080 \\
      --dns-port 5300

  # Then tell your client to use DNS 127.0.0.1:5300 and target http://api.example.com:8080
"""

import argparse
import threading
import time
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime

try:
    from dnslib import RR, A, QTYPE
    from dnslib.server import DNSServer, BaseResolver
except ImportError:
    sys.exit("Missing dependency: pip install dnslib")


# ---------------------------------------------------------------------------
# State shared between DNS server and HTTP servers
# ---------------------------------------------------------------------------

class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.dns_queries: list[dict] = []
        self.real_hits: list[dict] = []
        self.trap_hits: list[dict] = []   # non-empty = client NOT pinned

    def log_dns(self, query_num: int, ip_returned: str):
        entry = {"n": query_num, "ip": ip_returned, "time": datetime.now().isoformat()}
        with self.lock:
            self.dns_queries.append(entry)
        print(f"  [DNS]  query #{query_num} → {ip_returned}")

    def log_real(self, client_addr: str, path: str):
        entry = {"addr": client_addr, "path": path, "time": datetime.now().isoformat()}
        with self.lock:
            self.real_hits.append(entry)
        print(f"  [REAL] connection from {client_addr}  path={path}")

    def log_trap(self, client_addr: str, path: str):
        entry = {"addr": client_addr, "path": path, "time": datetime.now().isoformat()}
        with self.lock:
            self.trap_hits.append(entry)
        print(f"  [TRAP] *** connection from {client_addr}  path={path} ***")
        print("         --> client re-resolved DNS — IP is NOT pinned!")


STATE = State()


# ---------------------------------------------------------------------------
# Fake DNS server
# ---------------------------------------------------------------------------

class RebindingResolver(BaseResolver):
    def __init__(self, domain: str, real_ip: str, trap_ip: str):
        self.domain = domain.rstrip(".") + "."   # FQDN
        self.real_ip = real_ip
        self.trap_ip = trap_ip
        self._count = 0
        self._lock = threading.Lock()

    def resolve(self, request, handler):
        qname = str(request.q.qname)
        src_ip = handler.client_address[0]

        # Only count A record queries from non-GoDaddy sources
        # GoDaddy nameservers send NS queries to validate delegation — ignore them
        is_a_query = request.q.qtype == QTYPE.A

        if is_a_query:
            with self._lock:
                self._count += 1
                n = self._count
            # First A query → real IP (passes SSRF check); all subsequent → trap IP
            ip = self.real_ip if n == 1 else self.trap_ip
            STATE.log_dns(n, ip)
        else:
            # NS/MX/etc queries — just return real IP, don't advance counter
            ip = self.real_ip
            print(f"  [DNS]  non-A query ({request.q.qtype}) from {src_ip} → {ip} (counter unchanged)")

        reply = request.reply()
        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(ip), ttl=0))
        return reply


# ---------------------------------------------------------------------------
# HTTP servers (real + trap)
# ---------------------------------------------------------------------------

def _make_handler(label: str, log_fn):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            log_fn(self.client_address[0], self.path)
            body = f"{label} server — you reached {label}\n".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            self.do_GET()

        def log_message(self, fmt, *args):
            pass  # suppress default per-request stderr noise

    return Handler


def _start_http(label: str, ip: str, port: int, log_fn) -> threading.Thread | None:
    handler = _make_handler(label, log_fn)
    try:
        # Always bind to 0.0.0.0 — the ip argument is what DNS advertises,
        # not what we bind to (public/link-local IPs can't be bound directly).
        server = HTTPServer(("0.0.0.0", port), handler)
    except OSError as e:
        print(f"[!] Could not start {label} HTTP server on port {port}: {e}")
        return None
    t = threading.Thread(target=server.serve_forever, daemon=True,
                         name=f"http-{label}")
    t.server = server
    t.start()
    return t


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report():
    print("\n" + "=" * 60)
    print("VERIFICATION REPORT")
    print("=" * 60)

    print(f"\nDNS queries received : {len(STATE.dns_queries)}")
    for q in STATE.dns_queries:
        print(f"  #{q['n']:>2}  {q['time']}  → {q['ip']}")

    print(f"\nReal-server hits     : {len(STATE.real_hits)}")
    for h in STATE.real_hits:
        print(f"  {h['time']}  from {h['addr']}  {h['path']}")

    print(f"\nTrap-server hits     : {len(STATE.trap_hits)}")
    for h in STATE.trap_hits:
        print(f"  {h['time']}  from {h['addr']}  {h['path']}")

    print()
    if STATE.trap_hits:
        print("RESULT: FAIL — client re-resolved DNS and connected to the trap IP.")
        print("        The client has NOT implemented IP pinning correctly.")
    elif len(STATE.dns_queries) <= 1:
        print("RESULT: INCONCLUSIVE — only one DNS query seen so far.")
        print("        Ask the client to make multiple requests, then check again.")
    elif STATE.real_hits:
        print("RESULT: PASS — DNS was queried multiple times but the client")
        print("        kept connecting to the real (pinned) IP. IP pinning works.")
    else:
        print("RESULT: INCONCLUSIVE — no HTTP connections observed at all.")

    print("=" * 60)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Verify client IP pinning by simulating DNS rebinding"
    )
    parser.add_argument("--domain",    default="test.local",
                        help="Hostname the client will resolve (default: test.local)")
    parser.add_argument("--real-ip",   default="127.0.0.1",
                        help="IP returned for the FIRST DNS query (default: 127.0.0.1)")
    parser.add_argument("--real-port", type=int, default=8080,
                        help="Port for the real HTTP server (default: 8080)")
    parser.add_argument("--trap-ip",   default="127.0.0.2",
                        help="IP returned for all SUBSEQUENT DNS queries (default: 127.0.0.2)")
    parser.add_argument("--trap-port", type=int, default=8080,
                        help="Port for the trap HTTP server (default: 8080)")
    parser.add_argument("--dns-port",  type=int, default=5300,
                        help="UDP port for the fake DNS server (default: 5300)")
    args = parser.parse_args()

    print("DNS Rebinding Verification Tool")
    print("-" * 40)
    print(f"Domain   : {args.domain}")
    print(f"Real IP  : {args.real_ip}:{args.real_port}  (1st DNS answer)")
    print(f"Trap IP  : {args.trap_ip}:{args.trap_port}  (all subsequent DNS answers)")
    print(f"DNS port : {args.dns_port}")
    print()

    # Start HTTP servers (both bind to 0.0.0.0 — DNS advertises the real/trap IPs
    # but the machine cannot bind directly to public or link-local addresses)
    _start_http("REAL", args.real_ip, args.real_port, STATE.log_real)
    print(f"[+] Real HTTP server  listening on 0.0.0.0:{args.real_port}  (DNS tells client: {args.real_ip})")

    _start_http("TRAP", args.trap_ip, args.trap_port, STATE.log_trap)
    print(f"[+] Trap HTTP server  listening on 0.0.0.0:{args.trap_port}  (DNS tells client: {args.trap_ip})")

    # Start fake DNS — listen on all interfaces so the client can reach it
    resolver = RebindingResolver(args.domain, args.real_ip, args.trap_ip)
    dns_server = DNSServer(resolver, port=args.dns_port, address="0.0.0.0")
    dns_server.start_thread()
    print(f"[+] Fake DNS server   listening on 0.0.0.0:{args.dns_port}")

    print()
    print("Next steps:")
    print(f"  1. Tell the client to use DNS server: {args.real_ip}:{args.dns_port}")
    print(f"  2. Tell the client to send requests to: http://{args.domain}:{args.real_port}/")
    print(f"  3. Have the client make at least 2 requests.")
    print(f"  4. Press Ctrl+C here to see the verification report.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        dns_server.stop()
        print_report()


if __name__ == "__main__":
    main()
