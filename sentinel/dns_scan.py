import dns.resolver

class SubdomainScanner:
    def __init__(self, console):
        self.console = console
        self.common_subdomains = ['www', 'mail', 'dev', 'staging', 'api', 'test', 'blog', 'admin', 'portal', 'vpn', 'vps']

    def scan(self, domain):
        found = []
        with self.console.status(f"[bold cyan]Enumerating subdomains for {domain}..."):
            for sub in self.common_subdomains:
                target = f"{sub}.{domain}"
                try:
                    dns.resolver.resolve(target, 'A')
                    found.append(target)
                except:
                    pass
        return found
