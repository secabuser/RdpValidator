import socket
import threading
import concurrent.futures
import time
from pystyle import Colors, Colorate, Center
from colorama import Fore, init
from os import system, name
from tqdm import tqdm

init()

G = Fore.GREEN
R = Fore.RED
W = Fore.WHITE
RE = Fore.RESET
Y = Fore.YELLOW

class Scanner:
    def __init__(self, ip_file, threads, timeout, send_rdp, output_file):
        self.ip_file = ip_file
        self.threads = threads
        self.timeout = timeout
        self.send_rdp = send_rdp
        self.output_file = output_file
        self.targets = []
        self.lock = threading.Lock()
        self.good = 0
        self.bad = 0
        self.errors = 0
        self.checked = 0
        self.total = 0

    def clr(self):
        system("cls" if name == "nt" else "clear")

    def bnr(self):
        banner = '''
▗▄▄▖ ▗▄▄▄  ▗▄▄▖     ▗▖  ▗▖ ▗▄▖ ▗▖   ▗▄▄▄▖▗▄▄▄   ▗▄▖▗▄▄▄▖▗▄▖ ▗▄▄▖ 
▐▌ ▐▌▐▌  █ ▐▌ ▐▌    ▐▌  ▐▌▐▌ ▐▌▐▌     █  ▐▌  █ ▐▌ ▐▌ █ ▐▌ ▐▌▐▌ ▐▌
▐▛▀▚▖▐▌  █ ▐▛▀▘     ▐▌  ▐▌▐▛▀▜▌▐▌     █  ▐▌  █ ▐▛▀▜▌ █ ▐▌ ▐▌▐▛▀▚▖
▐▌ ▐▌▐▙▄▄▀ ▐▌        ▝▚▞▘ ▐▌ ▐▌▐▙▄▄▖▗▄█▄▖▐▙▄▄▀ ▐▌ ▐▌ █ ▝▚▄▞▘▐▌ ▐▌
                         
                         t.me/secabuser
'''
        print(Colorate.Diagonal(Colors.red_to_blue, Center.XCenter(banner)))

    def _lip(self):
        try:
            with open(self.ip_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("open tcp"):
                        parts = line.split()
                        ip = parts[3]
                        port = int(parts[2]) if parts[2].isdigit() else 3389
                        self.targets.append((ip, port))
                    elif ":" in line:
                        ip, port = line.split(":")
                        self.targets.append((ip, int(port)))
                    else:
                        self.targets.append((line, 3389))
            self.total = len(self.targets)
        except FileNotFoundError:
            print(f"{R}File not found ;]{RE}")
            exit(1)

    def _crl(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            if result != 0:
                sock.close()
                return False
            pkt = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
            sock.sendall(pkt)
            try:
                resp = sock.recv(1024)
                if resp and (b"\x0e\xe0" in resp or b"\x03\x00" in resp):
                    sock.close()
                    return True
                else:
                    sock.close()
                    return False
            except:
                sock.close()
                return False
        except:
            return False

    def _cp(self, target):
        ip, port = target
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                is_good = False
                if self.send_rdp:
                    is_good = self._crl(ip, port)
                else:
                    is_good = True
                if is_good:
                    with self.lock:
                        self.good += 1
                    with self.lock:
                        with open(self.output_file, "a") as f:
                            f.write(f"{ip}:{port}\n")
                    status_text = f"{G}[GOOD]{RE}"
                else:
                    status_text = f"{Y}[BAD]{RE}"
                    with self.lock:
                        self.bad += 1
            else:
                status_text = f"{R}[Closed]{RE}"
                with self.lock:
                    self.bad += 1
            sock.close()
        except:
            status_text = f"{Y}[Error]{RE}"
            with self.lock:
                self.errors += 1
        finally:
            with self.lock:
                self.checked += 1
        return f"{status_text} {ip}:{port}"

    def run(self):
        self._lip()
        self.clr()
        self.bnr()
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self._cp, target) for target in self.targets]
            with tqdm(total=self.total, ncols=100, bar_format="{desc}") as pbar:
                for future in concurrent.futures.as_completed(futures):
                    status = future.result()
                    elapsed = time.time() - start_time
                    per_sec = round(self.checked / elapsed, 1) if elapsed > 0 else 0
                    pbar.set_description_str(
                        f"Good: {self.good} | Bad: {self.bad} | Error: {self.errors} | Per/s: {per_sec}ip | {self.checked}/{self.total} Ips"
                    )
                    pbar.update(1)


if __name__ == "__main__":
    system("cls" if name == "nt" else "clear")
    scan = Scanner("", 0, 0, False, "output.txt")
    scan.bnr()
    ip_file = input(f"{W}IP file > {RE}").strip()
    try:
        threads = int(input(f"{W}Max threads > {RE}").strip())
        timeout = float(input(f"{W}Timeout (seconds) > {RE}").strip())
        send_rdp = input(f"{W}Full Test? (y/n) > {RE}").strip().lower() == "y"
        output_file = input(f"{W}Output file name > {RE}").strip()
    except:
        print(f"{R}Invalid input ;]{RE}")
        exit(1)
    scan.ip_file = ip_file
    scan.threads = threads
    scan.timeout = timeout
    scan.send_rdp = send_rdp
    scan.output_file = output_file
    scan.run()
