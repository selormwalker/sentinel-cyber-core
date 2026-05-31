import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class WebScanner:
    def __init__(self, console):
        self.console = console
        self.sensitive_files = [
            '.env', '.git/config', 'config.php', 'wp-config.php', 
            'settings.py', 'database.yml', '.htaccess', 'backup.sql',
            'package.json', 'composer.json', '.ssh/id_rsa'
        ]

    def scan_sensitive_files(self, base_url):
        found = []
        with self.console.status("[bold yellow]Scanning for sensitive files..."):
            for file in self.sensitive_files:
                target_url = urljoin(base_url, file)
                try:
                    res = requests.get(target_url, timeout=3, allow_redirects=False)
                    if res.status_code == 200:
                        found.append(file)
                except:
                    pass
        return found

    def find_links(self, url):
        links = set()
        try:
            res = requests.get(url, timeout=5)
            soup = BeautifulSoup(res.text, 'html.parser')
            for a in soup.find_all('a', href=True):
                link = urljoin(url, a['href'])
                if urlparse(link).netloc == urlparse(url).netloc:
                    links.add(link)
        except:
            pass
        return links
