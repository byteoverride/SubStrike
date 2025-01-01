# SubStrike

SubStrike is a comprehensive subdomain reconnaissance tool for penetration testers and security researchers. With advanced features like subdomain enumeration, directory brute-forcing, HTTP header analysis, subdomain takeover detection, and technology stack detection using the Wappalyzer API, SubStrike is your all-in-one solution for reconnaissance.

## Features

- **Subdomain Enumeration**: Enumerates subdomains using crt.sh and optional wordlists.
- **Status Code Analysis**: Retrieves HTTP status codes for each subdomain.
- **File Extension Checks**: Tests for specific file extensions on subdomains.
- **Directory Brute-forcing**: Leverages wordlists and file extensions to discover hidden directories and files.
- **Subdomain Takeover Detection**: Identifies subdomains vulnerable to takeover.
- **HTTP Header Analysis**: Scans for missing or insecure headers.
- **Technology Stack Detection**: Detects technologies used on subdomains via the Wappalyzer API.
- **Rate-Limiting**: Enforces controlled request rates to prevent server overload.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/byteoverride/SubStrike.git
    cd SubStrike
    ```

2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Set your Wappalyzer API key in the script:
    - Open `substrike.py` and replace `your_api_key_here` with your Wappalyzer API key.

## Usage

```bash
python substrike.py [options]
#-u, --url: Target domain (required).
#--wordlist: Path to a wordlist for subdomain or directory brute-forcing.
#--extensions: File extensions for brute-forcing (default: html, php, js, css).
#--headers: Analyze HTTP headers for security issues.
#--takeover: Check for subdomain takeover vulnerabilities.
#--tech: Detect technology stack for subdomains using Wappalyzer API.
#-o, --output: Save results to a file.
# -h help page
```
##Enumerate subdomains and analyze headers:
  	```bash
  		python3 substrike.py -u example.com --headers
  	```

##Perform directory brute-forcing with a wordlist and custom extensions:
	```bash	
		python3 substrike.py -u example.com --wordlist wordlist.txt --extensions html php
	```
 
##Detect technologies on subdomains using Wappalyzer:
	```bash
		python3 substrike.py -u example.com --tech
	```
 
##Save all results to a file:
	```bash
		python3 substrike.py -u example.com -o results.txt
	```
