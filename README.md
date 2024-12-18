# DNS Enumeration Tool

## Description

This DNS Enumeration Tool automates the process of discovering subdomains and related DNS records for a given domain. It integrates several external tools to perform thorough enumeration and helps you identify:

- **Subdomain Takeover Candidates:** Subdomains pointing to cloud services or external platforms that could be registered or hijacked.
- **Old or Deprecated Servers:** Historical subdomains that may lead to outdated or vulnerable infrastructure.
- **Unknown or Hidden Servers:** Unpublicized subdomains discovered through brute forcing or DNS records that might expose additional attack surfaces.

After enumeration, the tool can optionally open discovered subdomains in Firefox, run EyeWitness for screenshots and HTTP info, or simply exit with the results saved to files.

## Features

- Integrates multiple subdomain discovery methods:
  - Queries `crt.sh` (via the script's internal logic) for certificate-based subdomain enumeration.
  - Uses `waybackurls` to extract potential subdomains from archived URLs.
  - Uses `amass` in passive mode to find subdomains.
  - Uses `shuffledns` in brute force mode (if desired) to discover additional subdomains from a wordlist.
- Performs a final resolution check with `shuffledns` in resolver mode, filtering out wildcard DNS entries automatically.
- Uses `dnsx` to find and list CNAME records of the final resolved subdomains.
- Offers a final prompt to open discovered subdomains in Firefox, run Eyewitness to capture screenshots and HTTP headers, or do nothing.
- Stores outputs in a domain-specific output directory

## Installation

### Prerequisites

- Kali Linux (recommended) or a similar Debian-based environment with `sudo` privileges.
- `golang` installed for `go install` tools.
- `python3` (usually pre-installed on Kali).

### Tools Installed by the `install_deps.sh` Script

- **amass**: Subdomain enumeration tool.
- **jq**: For JSON parsing (used in various pipelines).
- **firefox-esr**: For opening found subdomains in browser tabs.
- **git**: For cloning and general version control operations.
- **python3-venv**: Python virtual environment support.
- **golang**: For installing Go-based tools.
- **eyewitness**: For automated reconnaissance (screenshots, HTTP info).
- **waybackurls**: For extracting URLs and subdomains from the Wayback Machine.
- **zdns**: For bulk DNS resolution if needed (optional).
- **shuffledns**: Handles DNS brute forcing and resolving final lists, filtering wildcards.
- **dnsx**: For extracting CNAME records and additional DNS data.

### Steps To Install
(The install dependencies script should cover all of this)
1. Clone this repository:
   **git clone https://github.com/kolbyn24personal/DNS_Enum**
   
   **cd <your-repo>**

2. Run the installation script(must run as sudo):
   **chmod +x ./install_deps.sh**
   **sudo ./install_deps.sh**


3. Verify the installation:
```
which amass
which waybackurls
which shuffledns
which dnsx
which eyewitness
which firefox
```   
   If these commands return paths (e.g., **/usr/local/bin/waybackurls**), the setup is complete.

## Usage

Run the tool with a target domain:
**./dns_enum.py --domain example.com**

Optional flags:
- **--no-certsh**: Skip querying crt.sh
- **--no-wayback**: Skip waybackurls step
- **--no-amass**: Skip amass enumeration
- **--no-bruteforce**: Skip brute forcing subdomains with shuffledns
- **--no-zdns**: Skip final shuffledns resolution check (not recommended)

Optional flags:
- **--wordlist to specify a custom wordlist**
- **--resolvers to specify a custom resolvers file**

Example:
```
./dns_enum.py --domain example.com --wordlist /path/to/wordlist.txt --resolvers /path/to/resolvers.txt


```
```
./dns_enum.py --domain example.com --no-wayback
```
```
./dns_enum.py --domain example.com --no-wayback --wordlist ~/my_wordlist.txt --resolvers ~/my_resolvers.txt
```
## Workflow

1. **Data Gathering:**  
   - Queries `crt.sh` to find certificate-based subdomains.
   - Uses `waybackurls` to find historical subdomains.
   - Uses `amass` in passive mode to find subdomains.
   - Optionally uses `shuffledns` in brute force mode against a chosen wordlist to uncover more subdomains.

2. **Combining Results:**  
   Merges all discovered subdomains into one list and removes duplicates.

3. **Final Resolution:**  
   Runs `shuffledns` in resolver mode to confirm which subdomains resolve properly, automatically filtering out wildcard DNS entries.

4. **CNAME Enumeration:**  
   Uses `dnsx` to find CNAME records for the resolved subdomains and saves them to a file.

5. **Final Prompt:**  
   After enumeration (WARNING: This goes from OISNT to active scanning after this step, do nothing if you are only performing OSINT):
   Found X subdomains for example.com.
   (F) Firefox | (E) Eyewitness | (N) Nothing
   
   Choose:
   - **F**: Open in Firefox
   - **E**: Run EyeWitness
   - **N**: Do nothing

## Interpreting the Output

Look for:
- **Subdomain Takeover Opportunities:** Unclaimed cloud resources or platforms
- **Old/Deprecated Servers:** Potentially vulnerable, outdated hosts
- **Unknown/Hidden Servers:** Admin panels, staging sites, internal tools

Next Steps:
- Inspect subdomains manually in a browser
- Use EyeWitness for quick overviews and screenshots
- Investigate endpoints, directories, or services for vulnerabilities

## Credit
This script was inspired by my notes file located here:
https://github.com/kolbyn24/Notes/blob/main/03%20-%20Content/DNS%20Enumeration.md
which was built using **Patrick Higgins** methodology and scripts.

What Changed between this note file and the final all in one script:

- The cert.sh logic is replaced by get_cert_subdomains() which uses Python’s requests and json to query crt.sh.
- The brute_subs.sh logic is handled by brute_force_subdomains() which uses massdns to brute force from a given wordlist.
- The bulk_resolve_dns.sh logic is essentially massdns_resolve() function, allowing us to resolve any list of domains using massdns.
- The script still uses amass, waybackurls, and massdns as installed tools, which can be installed via apt or go. No custom shell scripts are needed now.
- Probably other things, idk at this point

The notes file details a more manual and step-by-step approach, giving you full insight into how each step is performed and why. 

I encourage you to run through these notes and see if there is anything that was overlooked in this script, and if so, please feel free to contribute or suggest additions.

## Disclaimer

Use this tool only on domains you own or have permission to test. Unauthorized use may be illegal.

## Contributing

Contributions are welcome via issues or pull requests.



