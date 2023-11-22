import os
import urllib.request
import urllib.error
from urllib.parse import urlparse
import socket
import re
import json
import time
from datetime import datetime
import textwrap
from functools import wraps


_IPIFY_ADDRESS = 'https://geo.ipify.org/api/v2/country?apiKey=' + os.getenv('APIKEY_IPIFY') # type: ignore
_CURL_DOH_WIKI_ADDRESS = 'https://raw.githubusercontent.com/wiki/curl/curl/DNS-over-HTTPS.md'
_ADGUARD_DOH_WIKI_ADDRESS = 'https://raw.githubusercontent.com/AdguardTeam/KnowledgeBaseDNS/master/docs/general/dns-providers.md'


def timer(func):  # Decorator
    '''Print the runtime of the decorated function.'''
    @wraps(func)  # Restores metadata of the original func obj (.__name__, etc.)
    def wrapper(*args, **kwargs):
        print(f"*Timer: the function {func.__name__!r} has started.")
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        run_time = end_time - start_time
        print(f"*Timer: the function {func.__name__!r} has finished in {run_time:.4f}s.")  # !r explicitly returns as a string with ' '
        return result

    return wrapper


def get_ip_info_string():
    '''Get geolocation based on IP and return "Region, Country" string.'''
    try:
        with urllib.request.urlopen(_IPIFY_ADDRESS) as response:
            ip_info = json.loads(response.read().decode('utf-8'))
            return f"{ip_info['location']['region']}, {ip_info['location']['country']}"
    except urllib.error.HTTPError as e:
        if e.code == 403: # Capture 403 forbidden, throw otherwise.
            return f"Error 403 (forbidden), check ipify API key"
        else:
            raise


def strip_port(domain):
    '''Strips a port number if present in a domain (e.g. example.com:853 > example.com).'''
    if ":" in domain:
        return domain.split(":")[0]
    else:
        return domain


def get_valid_domain(url):
    '''Gets a plain domain by parsing a URL and striping port numbers if present.'''
    return strip_port(urlparse(url).netloc)


def sort_domains(domains):
    """Sorts a list of domains in alphabetical order by SLD, then subdomains,
    ignoring TLD.

    Parameters
    ----------
    domains : list
        The list of domains to sort

    Returns
    -------
    list
        The list of sorted domains
    """
    # Split each domain into it's parts (TLD, SLD, subdomains).
    split_domains = [domain.split('.')[::-1] for domain in domains]

    # Sort by SLD, then by each subdomain, ignoring TLD.
    sorted_domains = sorted(split_domains, key=lambda x: x[1:])

    # Join the domain parts back together, reverse them to original order.
    sorted_domains = ['.'.join(domain[::-1]) for domain in sorted_domains]

    return sorted_domains


def get_file_doh_domains(filename, domains=[]):
    """Get domains from a file that lists one domain per line.
    Ensure no duplicates, append to existing list if required.
    Note: domains are not validated.

    Parameters
    ----------
    filename : string
        The file containing domains
    domains : list, optional
        A list of domains to check for duplicates and append to, by default []

    Returns
    -------
    domains : list
        Parsed, non-duplicate domains
    stats : dict
        Match statistics
    """
    stats = {'matches': 0, 'adds': 0}

    with open(filename, 'r') as file:
        for line in file:
            domain = line.strip()
            if domain:
                stats['matches'] += 1
                if not domain in domains:
                    stats['adds'] += 1
                    domains.append(domain)
                
    print(f"Found {stats['matches']} domains in file '{filename}'. Added {stats['adds']} non-duplicate domain/s to the list.")
    return domains, stats


def get_curl_wiki_doh_domains(domains=[]):
    """Extract the DoH domains from the Curl DoH Wiki Page.

    Parameters
    ----------
    domains : list, optional
        A list of domains to check for duplicates and append to, by default []

    Returns
    -------
    domains : list
        Found valid, non-duplicate domains
    stats : dict
        Match statistics
    """
    # Retrieve the raw wiki content
    with urllib.request.urlopen(_CURL_DOH_WIKI_ADDRESS) as response:
        wiki_content = response.read().decode('utf-8')

    # Roughly narrow down the raw response to just the public DoH MD formatted table.
    start = wiki_content.find("# Publicly available servers")
    end = wiki_content.find("# Private DNS Server")
    trimmed_wiki_content = wiki_content[start:end]

    # Find all of the domains listed in the table.
    stats = {'matches': 0, 'adds': 0}
    rows = trimmed_wiki_content.split('\n')
    for row in rows:
        # Split the row into columns based on MD table formatting ('|')
        columns = row.split('|')

        # Find MD table rows, relies on formatting remaining the same. 0| 1 Who runs it | 2 Base URL | 3 Working* | 4 Comment |5
        if len(columns) >= 4:
            # Extract the 'Base URL' column
            base_url = columns[2].strip()

            # Find all URLs in the column
            url_matches = re.finditer(r"(https?\:\/\/)?[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)+(:[0-9]{1,5})?([\/\#\?][a-zA-Z0-9\-\.\_\?\,\'\/\\\+\&\;\:\%\$\#\=\~\[\]\@\!\*\+]*)?", base_url)

            # Convert each URL to a domain and append to domains list if it isn't a duplicate
            for url_match in url_matches:
                domain = get_valid_domain(url_match.group())
                # If valid domain found
                if domain:
                    stats['matches'] += 1
                    # If domain is not a duplicate
                    if not domain in domains:
                        stats['adds'] += 1
                        domains.append(domain)

    print(f"Found {stats['matches']} DoH domains in the Curl DoH Wiki. Added {stats['adds']} non-duplicate domain/s to the list.")
    return domains, stats


def get_adguard_wiki_doh_domains(domains=[]):
    """Extract the DoH domains from the AdGuard DNS Wiki Page.

    Parameters
    ----------
    domains : list, optional
        A list of domains to check for duplicates and append to, by default []

    Returns
    -------
    domains : list
        Found valid, non-duplicate domains
    stats : dict
        Match statistics
    """
    # Retrieve the raw wiki content
    with urllib.request.urlopen(_ADGUARD_DOH_WIKI_ADDRESS) as response:
        wiki_content = response.read().decode('utf-8')

    # Find all of the DoH domains in the MD tables in the content
    stats = {'matches': 0, 'adds': 0}
    rows = wiki_content.split('\n')
    for row in rows:
        # Split the row into columns based on MD table formatting ('|')
        columns = row.split('|')
        
        # Find MD table rows, relies on formatting being constant. 0| 1 Protocol | 2 Address | 3 Location |4
        if len(columns) == 5:
            protocol = columns[1].strip()
            address = columns[2].strip()

            # If this row is for DNS-over-HTTPS.
            if 'HTTPS' in protocol:
                url_matches = re.findall(r"`(.*?)`", address) # Domains are always surrounded by ` `
                for url_match in url_matches:
                    domain = get_valid_domain(url_match)
                    if domain:
                        stats['matches'] += 1
                        # If domain is not a duplicate
                        if not domain in domains:
                            stats['adds'] += 1
                            domains.append(domain)
    
    print(f"Found {stats['matches']} DoH domains in the AdGuard DNS Wiki. Added {stats['adds']} non-duplicate domain/s to the list.")
    return domains, stats


@timer
def resolve_domains(domains):
    """Resolve domains to IP addresses of servers registered to them.

    Parameters
    ----------
    domains : list
        The domains to resolve

    Returns
    -------
    ips_dict : dict
        The domains resolved to IPs {"example.com": [1.1.1.1, 1.0.0.1],}
    ips_flat : list
        All resolved IPs, no domain names
    failed_domains : list
        Domain names that failed to resolve
    """
    ips_dict = {}
    ips_flat = []
    failed_domains = []
    for domain in domains:
        try:
            # Get the full list of possible IPs for the domain.
            domain_ips = socket.gethostbyname_ex(domain)[2]
            
            # Construct the dict entry for this domain
            ips_dict[domain] = domain_ips
            
            # Add the IP/s to the flat list, excluding duplicates
            for ip in domain_ips:
                if not ip in ips_flat:
                    ips_flat.extend(domain_ips)
        except socket.gaierror:
            ips_dict[domain] = []
            failed_domains.append(domain)

    print(f"Resolved {len(domains)-len(failed_domains)}/{len(domains)} domains to IPs. Failed domains: {failed_domains if len(failed_domains) > 0 else 'none'}.")
    return ips_dict, ips_flat, failed_domains


def main():
    # Date, time string for the run time.
    time_now = f"{datetime.utcnow()} UTC"

    # Get the static known domains from file.
    domains, stats_file = get_file_doh_domains('doh_static_known_domains.txt')

    # Get domains from Curl Wiki (append without duplicates).
    domains, stats_curl = get_curl_wiki_doh_domains(domains)
    
    # Get domains from AdGuard Wiki (append without duplicates).
    domains, stats_adguard = get_adguard_wiki_doh_domains(domains)

    # Proper domain ordering for easier change tracking.
    domains = sort_domains(domains)

    # Resolve all domains to IP addresses.
    ips_dict, ips_flat, failed_domains = resolve_domains(domains)
    
    # Proper IP ordering for easier change tracking.
    ips = sorted(ips_flat, key=socket.inet_aton)

    # Write flat domains to txt file.
    with open('lists/doh_domains_plain.txt', 'w') as file:
        for index, domain in enumerate(domains):
            file.write(domain)
            if index != len(domains) - 1:
                file.write('\n')

    # Write flat ips to txt file.
    with open('lists/doh_ips_plain.txt', 'w') as file:
        for index, ip in enumerate(ips):
            file.write(ip)
            if index != len(ips) - 1:
                file.write('\n')

    # Write domain:[ip,] pairs to json file.
    with open('lists/doh_domains_ips.json', 'w') as file:
        file.write(json.dumps(ips_dict, indent="    "))
        
    # Write AdBlock-style domains to txt file.
    with open('lists/doh_domains_adblock.txt', 'w') as file:
        # Add a header
        header = f"!\n! Title: Public DoH Domains\n! Last updated: {time_now}\n! Domain count: {len(domains)}\n!\n! Generated by @jameshas/Public-DoH-Lists\n!\n"
        file.write(header)

        # Write domains to file "||domain.com^"
        for index, domain in enumerate(domains):
            file.write(f"||{domain}^")
            if index != len(domains) - 1:
                file.write('\n')
    
    # Write Hosts-style domains to txt file.
    with open('lists/doh_domains_hosts.txt', 'w') as file:
        # Add a header
        header = f"#\n# Title: Public DoH Domains\n# Last updated: {time_now}\n# Domain count: {len(domains)}\n#\n# Generated by @jameshas/Public-DoH-Lists\n#\n"
        file.write(header)

        # Write domains to file "0.0.0.0 domain.com"
        for index, domain in enumerate(domains):
            file.write(f"0.0.0.0 {domain}")
            if index != len(domains) - 1:
                file.write('\n')

    # Create a run stats string output.
    run_stats = textwrap.dedent(f"""\
        <!-- start_run-stats -->
        **Last run output**
        ```
        Ran at: {time_now}
        Unique domains: {len(domains)}
          - From file: {stats_file['adds']} unique ({stats_file['matches']} found)
          - From Curl wiki: {stats_curl['adds']} unique ({stats_curl['matches']} found)
          - From AdGuard wiki: {stats_adguard['adds']} unique ({stats_adguard['matches']} found)
        Unique IPs: {len(ips_flat)}
          - {len(failed_domains)} domains failed to resolve
          - Resolved local to {get_ip_info_string()}
        ```
        <!-- end_run-stats -->""")

    # Read the existing README.md.
    with open('README.md', 'r') as file:
        content = file.read()

    # Substitute the runstats section with the new output.
    new_content = re.sub(r'<!-- start_run-stats -->(.|\s)*?<!-- end_run-stats -->', run_stats, content)

    # Write the runstats updates back to README.md.
    with open('README.md', 'w') as file:
        file.write(new_content)


if __name__ == '__main__':
    main()
