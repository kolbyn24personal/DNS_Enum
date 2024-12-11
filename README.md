# DNS Enumeration Tool

## Description

This DNS Enumeration Tool automates the process of discovering subdomains and related DNS records for a given domain. It integrates several external tools to perform thorough enumeration and helps you identify:

- **Subdomain Takeover Candidates:** Subdomains pointing to cloud services or external platforms that could be registered or hijacked.
- **Old or Deprecated Servers:** Historical subdomains that may lead to outdated or vulnerable infrastructure.
- **Unknown or Hidden Servers:** Unpublicized subdomains discovered through brute forcing or DNS records that might expose additional attack surfaces.

After enumeration, the tool can optionally open discovered subdomains in Firefox, run EyeWitness for screenshots and HTTP info, or simply exit with the results saved to files.

## Features

- Integrates multiple subdomain discovery methods:
  - **cert.sh** (queries crt.sh for SSL-based subdomains)
  - **waybackurls** (retrieves historical subdomains from the Wayback Machine)
  - **amass** (comprehensive subdomain enumeration)
  - **brute_subs.sh** (brute forcing subdomains)
  - **zdns** (bulk DNS resolution checks)
- Deduplicates subdomains at multiple steps
- Filters out non-resolving subdomains and wildcard entries
- Allows skipping certain enumeration steps using --no-* flags
- Offers a final prompt to open subdomains in Firefox, run EyeWitness, or do nothing
- Stores outputs in a domain-specific output directory

## Installation

### Prerequisites

- Kali Linux (recommended) or similar Linux environment with sudo privileges
- Tools such as amass, jq, firefox-esr, git, python3-venv, golang, seclists, massdns, eyewitness
- A valid DNS resolvers file (e.g., /usr/share/seclists/Miscellaneous/dns-resolvers.txt)
- golang for installing waybackurls and zdns

### Steps
(The install dependencies script should cover all of this)
1. Clone this repository:
   **git clone https://github.com/kolbyn24personal/DNS_Enum**
   
   **cd <your-repo>**

2. Run the installation script:
   **./install_deps.sh**
   This will:
   - Install required packages and tools
   - Install waybackurls and zdns via go
   - Symlink any external scripts if present (not required now)

3. Verify the installation:
   **which waybackurls**
   
   **which zdns**
   
   **which eyewitness**
   
   **which cert.sh**
   
   **which brute_subs.sh**
   
   If these commands return paths (e.g., **/usr/local/bin/waybackurls**), the setup is complete.

## Usage

Run the tool with a target domain:
**./dns_enum.py --domain example.com**

Optional flags:
- **--no-certsh**
- **--no-wayback**
- **--no-amass**
- **--no-bruteforce**
- **--no-zdns**

Optional flags:
- **--wordlist to specify a custom wordlist**
- **--resolvers to specify a custom resolvers file**

Example:
```
./dns_enum.py --domain example.com --no-wayback
```
```
./dns_enum.py --domain example.com --no-wayback --wordlist ~/my_wordlist.txt --resolvers ~/my_resolvers.txt
```
## Workflow

1. **Subdomain Discovery:**
   - **cert.sh**: Finds subdomains via crt.sh
   - **waybackurls**: Historical subdomains from archive data
   - **amass**: Large-scale subdomain enumeration
   - **brute_subs.sh**: Brute forces potential subdomains

2. **Combining Results:**
   Results are combined, deduplicated, and saved to **example.com_all.txt**

3. **Filtering Wildcards:**
   Entries containing `*` move to **example.com_wildcards.txt**

4. **zdns Resolution Check:**
   If not skipped, **zdns** verifies which subdomains resolve.

5. **Final Prompt:**
   After enumeration:
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

## License

This project is licensed under the MIT License. See the **LICENSE** file for details.