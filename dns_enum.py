#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess
import requests
import json
from urllib.parse import urlparse

def run_command(cmd, exit_on_fail=False):
    result = subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        print(f"[!] Command failed: {cmd}\n{result.stderr}", file=sys.stderr)
        if exit_on_fail:
            sys.exit(1)
    return result.stdout.strip()

def get_cert_subdomains(domain):
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
                        line = line[2:]
                    if line and '.' in line:
                        subdomains.add(line)
            return sorted(subdomains)
        except Exception as e:
            print(f"[!] Error fetching crt.sh data with UA={ua}: {e}", file=sys.stderr)
    return []

def main():
    parser = argparse.ArgumentParser(description="DNS Enumeration Tool with shuffledns (handles wildcards)")
    parser.add_argument('--domain', '-d', required=True, help="Domain to enumerate")
    parser.add_argument('--wordlist', default="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt", help="Custom wordlist for brute forcing")
    parser.add_argument('--resolvers', default="/usr/share/seclists/Miscellaneous/dns-resolvers.txt", help="Path to resolvers file for shuffledns")

    parser.add_argument('--no-certsh', action='store_true', help="Skip cert.sh logic")
    parser.add_argument('--no-wayback', action='store_true', help="Skip waybackurls")
    parser.add_argument('--no-amass', action='store_true', help="Skip amass")
    parser.add_argument('--no-bruteforce', action='store_true', help="Skip brute forcing subdomains")
    parser.add_argument('--no-zdns', action='store_true', help="Skip final shuffledns resolution check")

    args = parser.parse_args()
    domain = args.domain

    output_dir = f"{domain}_output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    cert_file = os.path.join(output_dir, f"{domain}_certsh.txt")
    wayback_urls_file = os.path.join(output_dir, f"{domain}_wayback_urls.txt")
    wayback_subs_file = os.path.join(output_dir, f"{domain}_wayback_subdomains.txt")
    amass_file = os.path.join(output_dir, f"{domain}_amass.txt")
    brute_file = os.path.join(output_dir, f"{domain}_bruteforce.txt")
    all_file = os.path.join(output_dir, f"{domain}_all.txt")
    cname_file = os.path.join(output_dir, f"{domain}_cnames.txt")
    final_resolved_file = os.path.join(output_dir, f"{domain}_final_resolved.txt")

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

            wb_subs = set()
            for line in output.splitlines():
                try:
                    parsed = urlparse(line)
                    host = parsed.hostname if parsed.hostname else line
                    if host and '.' in host:
                        wb_subs.add(host)
                except ValueError:
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

    # brute forcing with shuffledns if not skipped
    if not args.no_bruteforce:
        print("[+] Brute forcing subdomains with shuffledns (domain+wordlist mode)...")
        if not os.path.exists(args.wordlist):
            print(f"[!] Wordlist not found at {args.wordlist}. Skipping brute force.", file=sys.stderr)
        else:
            # Use -mode bruteforce
            brute_cmd = f"shuffledns -d {domain} -w {args.wordlist} -r {args.resolvers} -o {brute_file} -mode bruteforce"
            run_command(brute_cmd)
            if os.path.exists(brute_file) and os.path.getsize(brute_file) > 0:
                with open(brute_file, 'r') as bf:
                    for line in bf:
                        line=line.strip()
                        if line and '.' in line:
                            subdomains.add(line)

    # Combine and deduplicate all found subdomains
    all_subs = sorted(subdomains)
    if all_subs:
        print("[+] Combining and deduplicating results...")
        with open(all_file, 'w') as f:
            f.write("\n".join(all_subs) + "\n")
    else:
        print("[!] No subdomains found.")
        open(all_file, 'w').close()

    # Final resolution check with shuffledns in list mode if not skipped
    if not args.no_zdns and all_subs:
        print("[+] Final resolution check with shuffledns (list mode, handles wildcards)...")
        # Use -mode resolver here
        shuffledns_cmd = f"shuffledns -list {all_file} -r {args.resolvers} -o {final_resolved_file} -mode resolve"
        run_command(shuffledns_cmd)
        if os.path.exists(final_resolved_file) and os.path.getsize(final_resolved_file) > 0:
            with open(final_resolved_file, 'r') as f:
                all_subs = [l.strip() for l in f if l.strip()]
        else:
            all_subs = []
    else:
        # If no final resolution step, we trust all_subs as is
        pass

    # Get CNAME information with dnsx if we have final resolved subs
    if all_subs:
        print("[+] Checking CNAME records with dnsx...")
        with open(final_resolved_file, 'w') as f:
            f.write("\n".join(all_subs) + "\n")

        dnsx_cmd = f"dnsx -cname -l {final_resolved_file} -silent"
        cname_output = run_command(dnsx_cmd)
        if cname_output:
            with open(cname_file, 'w') as cf:
                cf.write(cname_output + "\n")

    final_list = all_subs
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



if __name__ == "__main__":
    main()