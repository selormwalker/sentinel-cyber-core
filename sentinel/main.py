import typer
import requests
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from dotenv import load_dotenv
from google import genai
from urllib.parse import urlparse

# New module imports
from .scanner import PortScanner
from .web import WebScanner
from .dns_scan import SubdomainScanner

load_dotenv()
console = Console()
app = typer.Typer()

# Configure Gemini
api_key = os.getenv('GEMINI_API_KEY')
MODEL_ID = 'gemini-1.5-flash'
client = genai.Client(api_key=api_key) if api_key else None

@app.command()
def scan(target: str, full: bool = typer.Option(False, "--full", "-f", help="Perform a deep scan including ports and subdomains")):
    """
    Scan a target URL or domain for security vulnerabilities.
    """
    parsed_url = urlparse(target if target.startswith('http') else 'https://' + target)
    domain = parsed_url.netloc or parsed_url.path.split('/')[0]
    base_url = f"{parsed_url.scheme}://{domain}"

    console.print(Panel(f"🛡️  [bold white]SENTINEL CYBER CORE[/bold white] \n[dim]Target: {domain}[/dim]", border_style="blue"))

    findings = []

    # 1. Header Analysis
    _scan_headers(base_url, findings)

    # 2. Sensitive File Discovery
    web_scanner = WebScanner(console)
    sensitive_files = web_scanner.scan_sensitive_files(base_url)
    if sensitive_files:
        findings.append(f"Exposed sensitive files: {', '.join(sensitive_files)}")
        table = Table(title="Exposed Files", border_style="yellow")
        table.add_column("Path", style="red")
        for f in sensitive_files: table.add_row(f)
        console.print(table)

    if full:
        # 3. Port Scanning
        port_scanner = PortScanner(console)
        open_ports = port_scanner.scan(domain)
        if open_ports:
            findings.append(f"Open ports detected: {open_ports}")
            table = Table(title="Open Ports", border_style="cyan")
            table.add_column("Port", justify="right")
            table.add_column("Service", style="dim")
            services = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP"}
            for p in open_ports:
                table.add_row(str(p), services.get(p, "Unknown"))
            console.print(table)

        # 4. Subdomain Discovery
        dns_scanner = SubdomainScanner(console)
        subdomains = dns_scanner.scan(domain)
        if subdomains:
            findings.append(f"Discovered subdomains: {subdomains}")
            table = Table(title="Subdomains Discovered", border_style="blue")
            table.add_column("Subdomain", style="cyan")
            for s in subdomains: table.add_row(s)
            console.print(table)

    if findings and client:
        _ai_analysis(findings)
    else:
        console.print("[bold green]✔ No major vulnerabilities found.[/bold green]")

def _scan_headers(url, findings):
    headers_to_check = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy']
    try:
        response = requests.get(url, timeout=10)
        missing = [h for h in headers_to_check if h not in response.headers]
        
        table = Table(title="Security Headers")
        table.add_column("Header", style="cyan")
        table.add_column("Status")
        for h in headers_to_check:
            status = "[green]OK[/green]" if h in response.headers else "[red]MISSING[/red]"
            table.add_row(h, status)
        console.print(table)
        
        if missing:
            findings.append(f"Missing Security Headers: {missing}")
    except Exception as e:
        console.print(f"[bold red]Header Scan Error:[/bold red] {e}")

def _ai_analysis(findings):
    summary = "\n".join([f"- {f}" for f in findings])
    prompt = f"""
    You are a professional Cyber Security Analyst. Analyze the following findings from an automated scan:
    {summary}
    
    Provide a concise Executive Summary, Risk Assessment (Low/Medium/High), and actionable Remediation Steps.
    Use Markdown.
    """
    with console.status("[bold green]Generating AI Risk Assessment..."):
        try:
            response = client.models.generate_content(model=MODEL_ID, contents=prompt)
            console.print(Panel(response.text, title="📊 AI RISK ASSESSMENT", border_style="red"))
        except Exception as e:
            console.print(f"[yellow]AI Analysis failed: {e}[/yellow]")

if __name__ == "__main__":
    app()
