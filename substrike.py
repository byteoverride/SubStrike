import argparse
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
import os
import dns.resolver
import time
from termcolor import colored
import asyncio
import aiohttp
import random

# Configuration for SubStrike
PROXIES = [
    'http://proxy1:port',
    'http://proxy2:port',
    # Add more proxies as needed
]
MAX_REQUESTS_PER_MINUTE = 60
REQUEST_INTERVAL = 60 / MAX_REQUESTS_PER_MINUTE  # Rate limiting interval
THREAD_POOL_SIZE = 10
SUPPORTED_APIS = ['crt.sh']
WAPPALYZER_API_URL = 'https://api.wappalyzer.com/v2/lookup/'
WAPPALYZER_API_KEY = 'your_api_key_here'

# Banner
BANNER = """
███████╗██╗   ██╗██████╗ ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
██╔════╝██║   ██║██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
███████╗██║   ██║██████╔╝███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
╚════██║██║   ██║██╔══██╗╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
███████║╚██████╔╝██████╔╝███████║   ██║   ██║  ██║██║██║  ██╗███████╗
╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

SubStrike:Subdomain Reconnaissance Tool
Developer: Byte Override
Contact: psalmschristophermatovu@gmail.com
"""

# Verbose Logger
def log_verbose(message):
    print(colored(f"[VERBOSE] {message}", "blue"))

# Rate-Limited GET Request
def rate_limited_get(url):
    time.sleep(REQUEST_INTERVAL)  # Enforce rate limiting
    try:
        response = requests.get(url, timeout=5)
        return response
    except Exception as e:
        log_verbose(f"Error during GET request: {e}")
        return None

# Load wordlist
def load_wordlist(wordlist_path):
    try:
        with open(wordlist_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(colored(f"Error loading wordlist: {e}", "red"))
        return []

# Directory and File Brute-forcing
def dirsearch(subdomain, extensions, wordlist):
    results = []
    try:
        for word in wordlist:
            for ext in extensions:
                url = urljoin(f"http://{subdomain}", f"{word}.{ext}")
                response = rate_limited_get(url)
                if response and response.status_code == 200:
                    results.append((url, response.status_code))
                    log_verbose(f"Found: {url} ({response.status_code})")
    except Exception as e:
        log_verbose(f"Error during directory brute-forcing for {subdomain}: {e}")
    return results

# Detect technologies using Wappalyzer API
def detect_technologies_wappalyzer(subdomain):
    try:
        headers = {
            'x-api-key': WAPPALYZER_API_KEY
        }
        params = {
            'url': f"http://{subdomain}"
        }
        response = requests.get(WAPPALYZER_API_URL, headers=headers, params=params)
        if response.status_code == 200:
            tech_data = response.json()
            if tech_data:
                technologies = [app['name'] for app in tech_data[0]['technologies']]
                log_verbose(f"Technologies detected for {subdomain}: {technologies}")
                return technologies
        else:
            log_verbose(f"Wappalyzer API error: {response.status_code} - {response.text}")
    except Exception as e:
        log_verbose(f"Error detecting technologies for {subdomain}: {e}")
    return []

# Main function
async def main():
    print(colored(BANNER, "green"))

    parser = argparse.ArgumentParser(description="SubStrike: The Ultimate Subdomain Reconnaissance Tool")
    parser.add_argument("-u", "--url", required=True, help="Target domain")
    parser.add_argument("--wordlist", help="Path to wordlist for subdomains or directory brute-forcing")
    parser.add_argument("--extensions", nargs="*", default=["html", "php", "js", "css"], help="List of extensions for directory brute-forcing")
    parser.add_argument("--headers", action="store_true", help="Analyze HTTP headers for security issues")
    parser.add_argument("--takeover", action="store_true", help="Check for subdomain takeover vulnerabilities")
    parser.add_argument("--tech", action="store_true", help="Detect technology stack for subdomains using Wappalyzer API")
    parser.add_argument("-o", "--output", help="Save output to a file")

    args = parser.parse_args()
    domain = args.url

    # Load wordlist if provided
    wordlist = []
    if args.wordlist:
        log_verbose(f"Loading wordlist from {args.wordlist}")
        wordlist = load_wordlist(args.wordlist)
        log_verbose(f"Loaded {len(wordlist)} entries from the wordlist")

    subdomains = dynamic_subdomain_discovery(domain)

    print(colored(f"[*] Found {len(subdomains)} subdomains.", "yellow"))

    results = []
    header_issues = {}
    tech_results = {}
    dir_results = {}

    async with aiohttp.ClientSession() as session:
        tasks = [grab_status_code(sub, session) for sub in subdomains]
        results = await asyncio.gather(*tasks)

    if args.headers:
        for subdomain in subdomains:
            header_issues[subdomain] = analyze_headers(subdomain)

    if args.takeover:
        for subdomain in subdomains:
            vulnerable, cname = check_subdomain_takeover(subdomain)
            if vulnerable:
                print(colored(f"[!] Takeover Vulnerable: {subdomain} (CNAME: {cname})", "green"))

    if args.tech:
        for subdomain in subdomains:
            tech_results[subdomain] = detect_technologies_wappalyzer(subdomain)

    if wordlist:
        for subdomain in subdomains:
            dir_results[subdomain] = dirsearch(subdomain, args.extensions, wordlist)

    # Summary
    print(colored("\n[SUMMARY]", "cyan"))
    print(colored(f"[*] Total Subdomains Found: {len(subdomains)}", "yellow"))

    if args.headers:
        print(colored(f"[*] Header Issues: {len(header_issues)}", "yellow"))
    if args.tech:
        print(colored(f"[*] Technologies Detected: {len(tech_results)}", "yellow"))
    if wordlist:
        print(colored(f"[*] Directory Brute-forcing Results: {len(dir_results)}", "yellow"))

    if args.output:
        print(colored(f"[*] Saving results to {args.output}...", "cyan"))
        with open(args.output, "w") as file:
            file.write(f"Subdomains Found: {len(subdomains)}\n")
            for sub, code in results:
                file.write(f"{sub}: {code}\n")
            for subdomain, issues in header_issues.items():
                file.write(f"Headers ({subdomain}): {', '.join(issues)}\n")
            for subdomain, tech in tech_results.items():
                file.write(f"Tech ({subdomain}): {', '.join(tech)}\n")
            for subdomain, dirs in dir_results.items():
                for url, code in dirs:
                    file.write(f"DirSearch ({subdomain}): {url} ({code})\n")

if __name__ == "__main__":
    asyncio.run(main())
