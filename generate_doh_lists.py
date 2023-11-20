import time
from functools import wraps
import urllib.request
from urllib.parse import urlparse
import re
import socket
import json
from datetime import datetime


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


def strip_port(domain):
    '''Strips a port number if present in a domain (e.g. example.com:853 > example.com).'''
    if ":" in domain:
        return domain.split(":")[0]
    else:
        return domain


def get_valid_domain(url):
    '''Gets a plain domain by parsing a URL and striping port numbers if present.'''
    return strip_port(urlparse(url).netloc)


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
    list
        Parsed domains
    """
    matches = 0
    adds = 0

    with open(filename, 'r') as file:
        for line in file:
            domain = line.strip()
            if domain:
                matches += 1
                if not domain in domains:
                    adds += 1
                    domains.append(domain)
                
    print(f"Found {matches} domains in file '{filename}'. Added {adds} non-duplicate domain/s to the list.")
    return domains


def get_curl_wiki_doh_domains(domains=[]):
    """Extract the DoH domains from the Curl DoH Wiki Page.

    Parameters
    ----------
    domains : list, optional
        A list of domains to check for duplicates and append to, by default []

    Returns
    -------
    list
        Found valid domains
    """
    # Retrieve the raw wiki content
    with urllib.request.urlopen(_CURL_DOH_WIKI_ADDRESS) as response:
        wiki_content = response.read().decode('utf-8')

    # Roughly narrow down the raw response to just the public DoH MD formatted table.
    start = wiki_content.find("# Publicly available servers")
    end = wiki_content.find("# Private DNS Server")
    trimmed_wiki_content = wiki_content[start:end]

    # Find all of the domains listed in the table.
    matches = 0
    adds = 0
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
                    matches += 1
                    # If domain is not a duplicate
                    if not domain in domains:
                        adds += 1
                        domains.append(domain)

    print(f"Found {matches} DoH domains in the Curl DoH Wiki. Added {adds} non-duplicate domain/s to the list.")
    return domains


def get_adguard_wiki_doh_domains(domains=[]):
    """Extract the DoH domains from the AdGuard DNS Wiki Page.

    Parameters
    ----------
    domains : list, optional
        A list of domains to check for duplicates and append to, by default []

    Returns
    -------
    list
        Found valid domains
    """
    # Retrieve the raw wiki content
    with urllib.request.urlopen(_ADGUARD_DOH_WIKI_ADDRESS) as response:
        wiki_content = response.read().decode('utf-8')

    # Find all of the DoH domains in the MD tables in the content
    matches = 0
    adds = 0
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
                        matches += 1
                        # If domain is not a duplicate
                        if not domain in domains:
                            adds += 1
                            domains.append(domain)
    
    print(f"Found {matches} DoH domains in the AdGuard DNS Wiki. Added {adds} non-duplicate domain/s to the list.")
    return domains


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
    return ips_dict, ips_flat


def main():
    # Get the static known domains from file.
    domains = get_file_doh_domains('doh_static_known_domains.txt')

    # Get domains from Curl Wiki (append).
    domains = get_curl_wiki_doh_domains(domains)
    
    # Get domains from AdGuard Wiki (append).
    domains = get_adguard_wiki_doh_domains(domains)

    # Alphabetical domain ordering for easier change tracking.
    domains.sort()

    # Resolve all domains to IP addresses.
    ips_dict, ips_flat = resolve_domains(domains)
    
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
        header = f"!\n! Title: Public DoH Domains\n! Last modified: {datetime.now()}\n! Domain count: {len(domains)}\n!\n! Generated by @jameshas/Public-DoH-Lists\n!\n"
        file.write(header)

        # Write domains to file "||domain.com^"
        for index, domain in enumerate(domains):
            file.write(f"||{domain}^")
            if index != len(domains) - 1:
                file.write('\n')
    
    # Write Hosts-style domains to txt file.
    with open('lists/doh_domains_hosts.txt', 'w') as file:
        # Add a header
        header = f"#\n# Title: Public DoH Domains\n# Last modified: {datetime.now()}\n# Domain count: {len(domains)}\n#\n# Generated by @jameshas/Public-DoH-Lists\n#\n"
        file.write(header)

        # Write domains to file "0.0.0.0 domain.com"
        for index, domain in enumerate(domains):
            file.write(f"0.0.0.0 {domain}")
            if index != len(domains) - 1:
                file.write('\n')


if __name__ == '__main__':
    main()
