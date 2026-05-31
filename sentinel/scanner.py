import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from rich.progress import Progress, SpinnerColumn, TextColumn

class PortScanner:
    def __init__(self, console):
        self.console = console
        self.open_ports = []

    def _scan_port(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((host, port)) == 0:
                    self.open_ports.append(port)
        except:
            pass

    def scan(self, host, ports=None):
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
        
        self.open_ports = []
        host_ip = socket.gethostbyname(host)
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=self.console) as progress:
            task = progress.add_task(f"[cyan]Scanning ports on {host}...", total=len(ports))
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                for port in ports:
                    executor.submit(self._scan_port, host_ip, port)
                    progress.advance(task)
                    
        return self.open_ports
