#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess
import requests
import json
import tempfile
from urllib.parse import urlparse

def run_command(cmd, exit_on_fail=False):
    """Run a shell command and return stdout. Print errors if any.
    If exit_on_fail=True and command fails, exit the script.
    Otherwise, just print a warning and continue."""
    result = subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        print(f"[!] Command failed: {cmd}\n{result.stderr}", file=sys.stderr)
        if exit_on_fail:
            sys.exit(1)
    return result.stdout.strip()

def get_cert_subdomains(domain):
    """
    Fetch subdomains from crt.sh for the given domain using requests.
    Try one User-Agent, if fail, try another one.
    """
    url = f"https://crt.sh/?q={domain}&output=json"
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (X11; Linux x86_64; rv:70.0)"
    ]
    for ua in user_agents:
        try:
            resp = requests.get(url, headers={"User-Agent": ua}, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            subdomains = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for line in name_value.split('\n'):
                    line = line.strip()
                    if line.startswith('*.'):
                        line = line[2:]  # remove '*.'
                    if line and '.' in line:
                        subdomains.add(line)
            return sorted(subdomains)
        except Exception as e:
            print(f"[!] Error fetching crt.sh data with UA={ua}: {e}", file=sys.stderr)
            # try next user agent
    return []

def massdns_resolve(domains, resolvers, record_type="A"):
    """
    Uses massdns to resolve a list of domains for A or CNAME records.
    record_type: "A" or "CNAME"
    """
    if not domains:
        return []
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as domain_file:
        domain_file_path = domain_file.name
        for d in domains:
            domain_file.write(d + "\n")
    massdns_output = tempfile.NamedTemporaryFile(mode='r', delete=False)
    massdns_output_path = massdns_output.name
    massdns_output.close()

    cmd = f"massdns -r {resolvers} -t {record_type} -o S -w {massdns_output_path} {domain_file_path}"
    run_command(cmd)
    
    results = set()
    if os.path.exists(massdns_output_path):
        with open(massdns_output_path, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) > 0:
                    host = parts[0].rstrip('.')
                    if '.' in host:
                        if record_type == "A":
                            results.add(host)
                        elif record_type == "CNAME":
                            # Format: host CNAME target
                            if len(parts) >= 3 and parts[1] == "CNAME":
                                target = parts[2].rstrip('.')
                                results.add(f"{host},{target}")
    os.remove(domain_file_path)
    os.remove(massdns_output_path)
    return sorted(results)

def brute_force_subdomains(domain, wordlist, resolvers):
    """
    Brute force subdomains by appending them from a wordlist and resolving with massdns.
    """
    if not os.path.exists(wordlist):
        print(f"[!] Wordlist not found at {wordlist}", file=sys.stderr)
        return []
    to_resolve = []
    with open(wordlist, 'r') as wl:
        for line in wl:
            sub = line.strip()
            if sub:
                to_resolve.append(f"{sub}.{domain}")
    return massdns_resolve(to_resolve, resolvers=resolvers, record_type="A")

def main():
    parser = argparse.ArgumentParser(description="DNS Enumeration Tool (Integrated scripts)")
    parser.add_argument('--domain', '-d', help="Domain to enumerate", required=True)
    parser.add_argument('--wordlist', help="Custom wordlist for brute forcing", default="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
    parser.add_argument('--resolvers', help="Path to resolvers file for massdns", default="/usr/share/seclists/Miscellaneous/dns-resolvers.txt")

    # Flags to skip certain tools
    parser.add_argument('--no-certsh', action='store_true', help="Skip cert.sh logic")
    parser.add_argument('--no-wayback', action='store_true', help="Skip waybackurls")
    parser.add_argument('--no-amass', action='store_true', help="Skip amass")
    parser.add_argument('--no-bruteforce', action='store_true', help="Skip brute forcing subdomains")
    parser.add_argument('--no-zdns', action='store_true', help="Skip final A record resolution check")

    args = parser.parse_args()
    domain = args.domain

    # Create output directory
    output_dir = f"{domain}_output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    cert_file = os.path.join(output_dir, f"{domain}_certsh.txt")
    wayback_urls_file = os.path.join(output_dir, f"{domain}_wayback_urls.txt")
    wayback_subs_file = os.path.join(output_dir, f"{domain}_wayback_subdomains.txt")
    amass_file = os.path.join(output_dir, f"{domain}_amass.txt")
    brute_file = os.path.join(output_dir, f"{domain}_bruteforce.txt")
    all_file = os.path.join(output_dir, f"{domain}_all.txt")
    wildcards_file = os.path.join(output_dir, f"{domain}_wildcards.txt")
    cname_file = os.path.join(output_dir, f"{domain}_cnames.txt")

    subdomains = set()

    # cert.sh logic
    if not args.no_certsh:
        print("[+] Fetching subdomains from crt.sh (cert.sh logic)")
        cert_subs = get_cert_subdomains(domain)
        if cert_subs:
            with open(cert_file, 'w') as f:
                f.write("\n".join(cert_subs) + "\n")
            subdomains.update(cert_subs)
        else:
            print("[!] No subdomains found via crt.sh or request failed, continuing...")

    # waybackurls
    if not args.no_wayback:
        print("[+] Running waybackurls...")
        wayback_cmd = f"echo {domain} | waybackurls"
        output = run_command(wayback_cmd)
        if output:
            with open(wayback_urls_file, 'w') as f:
                f.write(output + "\n")

            # Extract subdomains from wayback URLs
            wb_subs = set()
            for line in output.splitlines():
                try:
                    parsed = urlparse(line)
                    host = parsed.hostname if parsed.hostname else line
                    if host and '.' in host:
                        wb_subs.add(host)
                except ValueError:
                    # Invalid URL (e.g. Invalid IPv6 URL), skip
                    continue
            if wb_subs:
                wb_subs = sorted(wb_subs)
                with open(wayback_subs_file, 'w') as f:
                    f.write("\n".join(wb_subs) + "\n")
                subdomains.update(wb_subs)
        else:
            print("[!] waybackurls returned no output or failed, continuing...")

    # amass
    if not args.no_amass:
        print("[+] Running amass...")
        run_command(f"amass enum -silent -passive -timeout 2 -d {domain} -o {amass_file}")
        if os.path.exists(amass_file) and os.path.getsize(amass_file) > 0:
            with open(amass_file, 'r') as f:
                for line in f:
                    line=line.strip()
                    if line and '.' in line:
                        subdomains.add(line)

    # brute force subdomains
    if not args.no_bruteforce:
        print("[+] Brute forcing subdomains...")
        brute_subs = brute_force_subdomains(domain, args.wordlist, args.resolvers)
        if brute_subs:
            with open(brute_file, 'w') as f:
                f.write("\n".join(brute_subs) + "\n")
            subdomains.update(brute_subs)

    # Combine and deduplicate all found subdomains
    all_subs = sorted(subdomains)
    if all_subs:
        print("[+] Combining and deduplicating results...")
        with open(all_file, 'w') as f:
            f.write("\n".join(all_subs) + "\n")
    else:
        print("[!] No subdomains found.")
        open(all_file, 'w').close()

    # Final resolution check if not skipped (ensure subdomains resolve)
    if not args.no_zdns and all_subs:
        print("[+] Final resolution check with massdns A record...")
        final_resolved = massdns_resolve(all_subs, args.resolvers, record_type="A")
        if final_resolved:
            all_subs = sorted(set(final_resolved))
            with open(all_file, 'w') as f:
                f.write("\n".join(all_subs) + "\n")
        else:
            # If none resolved
            with open(all_file, 'w') as f:
                pass
            all_subs = []

    # Check CNAME records for final subs
    if all_subs:
        print("[+] Checking CNAME records for final subdomains...")
        cname_results = massdns_resolve(all_subs, args.resolvers, record_type="CNAME")
        if cname_results:
            # cname_results are lines like "host,target"
            with open(cname_file, 'w') as f:
                for line in cname_results:
                    f.write(line + "\n")

    # Separate wildcards
    final_list = []
    if os.path.exists(all_file) and os.path.getsize(all_file) > 0:
        with open(all_file, 'r') as f:
            final_list = [l.strip() for l in f if l.strip() != ""]
        wildcards = [x for x in final_list if '*' in x]
        clean = [x for x in final_list if '*' not in x]

        # Deduplicate clean
        clean = sorted(set(clean))

        with open(all_file, 'w') as f:
            if clean:
                f.write("\n".join(clean) + "\n")

        if wildcards:
            with open(wildcards_file, 'w') as f:
                f.write("\n".join(sorted(set(wildcards))) + "\n")

        final_list = clean
    else:
        final_list = []

    count = len(final_list)
    print(f"Found {count} resolved subdomains for {domain}.")

    if count == 0:
        print("No subdomains found to proceed with Firefox or Eyewitness.")
    else:
        print("(F) Firefox | (E) Eyewitness | (N) Nothing")
        choice = input("Choose an option: ").strip().upper()

        if choice == 'F':
            if count > 0:
                print("[+] Opening subdomains in Firefox...")
                os.system("firefox " + " ".join(final_list))
            else:
                print("[!] No subdomains found to open.")
        elif choice == 'E':
            if count > 0:
                print("[+] Running Eyewitness...")
                targets_file = os.path.join(output_dir, f"{domain}_eyewitness_targets.txt")
                with open(targets_file, 'w') as tf:
                    tf.write("\n".join(final_list) + "\n")
                os.system(f"eyewitness --web -f {targets_file} -d {os.path.join(output_dir, domain + '_eyewitness')} --no-prompt")
                print(f"[+] Eyewitness report saved in {os.path.join(output_dir, domain + '_eyewitness')}")
            else:
                print("[!] No subdomains found to run Eyewitness on.")
        else:
            print("No action taken.")

    # Print a helpful one-liner at the end:
    print("\n[+] To attempt to resolve full URLs (like those from waybackurls) using zdns, you could do something like:")
    print("cat path/to/full_urls.txt | sed 's|^http://||; s|^https://||; s|/.*||' | sort -u | zdns A -threads 10 | jq -r '.data.answers[].answer' > resolved_ips.txt")

if __name__ == "__main__":
    main()
