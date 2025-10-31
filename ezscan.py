import argparse
import socket
import ipaddress
import os
import sys
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Dict
from datetime import datetime

class PortScanner:
    def __init__(self, input_file: str, output_file: str, threads: int, ports: List[int], timeout: float, look: int):
        self.input_file = input_file
        self.output_file = output_file
        self.threads = threads
        self.ports = ports
        self.timeout = timeout / 1000
        self.look = look
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.file_lock = threading.Lock()
        self.open_ports_found: Set[str] = set()
        self.host_ports: Dict[str, List[int]] = {}
        self.written_hosts: Set[str] = set()

        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        print("\n[!] Ctrl+C — Stopping scan...")
        self.stop_event.set()

    def write_header(self):
        if os.path.exists(self.output_file):
            return
        os.makedirs(os.path.dirname(self.output_file) or '.', exist_ok=True)
        with open(self.output_file, 'w') as f:
            f.write(f"# Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Input: {self.input_file} | Threads: {self.threads} | Timeout: {self.timeout*1000}ms\n")
            f.write(f"# Ports: {', '.join(map(str, self.ports))}\n")
            f.write(f"# Format: {'IP' if self.look == 1 else 'IP:port,port,port'}\n\n")

    def append_or_update(self, host: str, port: int):
        with self.lock:
            self.open_ports_found.add(host)
            self.host_ports.setdefault(host, []).append(port)
            self.host_ports[host] = sorted(set(self.host_ports[host]))

            if self.look == 1:
                if host not in self.written_hosts:
                    self.append_result(host)
                    self.written_hosts.add(host)
            else:  # look == 2
                self.update_host_line(host)

    def append_result(self, line: str):
        with self.file_lock:
            with open(self.output_file, 'a') as f:
                f.write(line + "\n")

    def update_host_line(self, host: str):
        try:
            with self.file_lock:
                if not os.path.exists(self.output_file):
                    return
                with open(self.output_file, 'r') as f:
                    lines = f.readlines()

                new_line = f"{host}:{','.join(map(str, self.host_ports[host]))}\n"
                found = False
                with open(self.output_file, 'w') as f:
                    for line in lines:
                        if line.strip() and not line.startswith('#'):
                            if line.strip().startswith(host + ':') or line.strip() == host:
                                if not found:
                                    f.write(new_line)
                                    found = True
                                continue
                        f.write(line)
                    if not found:
                        f.write(new_line)
        except:
            pass

    def scan_port(self, host: str, port: int):
        if self.stop_event.is_set():
            return None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return (host, port, result == 0)
        except:
            return (host, port, False)

    def parse_ips_from_file(self) -> Set[str]:
        ips = set()
        try:
            with open(self.input_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    ips.update(self.parse_ip_input(line))
        except FileNotFoundError:
            print(f"[!] File {self.input_file} not found!")
            sys.exit(1)
        return ips

    def parse_ip_input(self, ip_str: str) -> Set[str]:
        ips = set()
        try:
            if '/' in ip_str:
                net = ipaddress.ip_network(ip_str, strict=False)
                ips.update(str(ip) for ip in net.hosts())
            elif '-' in ip_str and '.' in ip_str.split('-', 1)[0]:
                s, e = ip_str.split('-', 1)
                start = ipaddress.ip_address(s.strip())
                end = ipaddress.ip_address(e.strip())
                if start > end:
                    start, end = end, start
                cur = start
                while cur <= end:
                    ips.add(str(cur))
                    cur += 1
            else:
                ips.add(str(ipaddress.ip_address(ip_str.strip())))
        except Exception as e:
            print(f"[!] IP Error '{ip_str}': {e}")
        return ips

    def run(self):
        print(f"[+] Launching scan...")
        print(f"[+] Input: {self.input_file}")
        print(f"[+] Output: {self.output_file}")
        print(f"[+] Threads: {self.threads}")
        print(f"[+] Port: {', '.join(map(str, self.ports))}")
        print(f"[+] Look: {'IP' if self.look == 1 else 'IP:Port'}")
        print(f"[+] Ctrl+C — Stop scan\n")

        self.write_header()
        hosts = self.parse_ips_from_file()
        print(f"[+] Hosts number: {len(hosts)}")

        if not hosts:
            return

        tasks = [(host, port) for host in hosts for port in self.ports]
        print(f"[+] Tasks number: {len(tasks)}")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_task = {
                executor.submit(self.scan_port, host, port): (host, port)
                for host, port in tasks
            }

            try:
                for future in as_completed(future_to_task):
                    if self.stop_event.is_set():
                        break
                    result = future.result()
                    if result and result[2]:  # open
                        host, port, _ = result
                        print(f"[OPEN] {host}:{port}")
                        self.append_or_update(host, port)
            except KeyboardInterrupt:
                print("\n[!] Stopping...")
                self.stop_event.set()

            for future in future_to_task:
                future.cancel()

        total_ports = sum(len(p) for p in self.host_ports.values())
        with self.file_lock:
            with open(self.output_file, 'a') as f:
                f.write(f"\n# Scan finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Hosts with open ports: {len(self.open_ports_found)}\n")
                f.write(f"# Open ports found: {total_ports}\n")

        print(f"\n[+] Done! Hosts found: {len(self.open_ports_found)}, ports found: {total_ports}")
        print(f"[+] Result: {self.output_file}")


def parse_ports(s: str) -> List[int]:
    ports = set()
    for p in s.split(','):
        p = p.strip()
        if '-' in p:
            start, end = map(int, p.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(p))
    return sorted(ports)


def main():
    parser = argparse.ArgumentParser(description="Сканнер портов с мгновенным выводом и Ctrl+C")
    parser.add_argument('-i', '--input', required=True)
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('-t', '--threads', type=int, default=128)
    parser.add_argument('-p', '--ports', required=True)
    parser.add_argument('-n', '--timeout', type=int, default=3000)
    parser.add_argument('-l', '--look', type=int, choices=[1, 2], default=2)

    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except:
        print("[!] Err -p. Пример: 80,443 или 1-1000")
        sys.exit(1)

    scanner = PortScanner(
        input_file=args.input,
        output_file=args.output,
        threads=args.threads,
        ports=ports,
        timeout=args.timeout,
        look=args.look
    )
    scanner.run()


if __name__ == "__main__":
    import threading
    main()