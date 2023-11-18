import time
from functools import wraps
import urllib.request
from urllib.parse import urlparse
import re
import socket
import json


def timer(func):  # Decorator
    '''Print the runtime of the decorated function.'''
    @wraps(func)  # Restores metadata of the original func obj (.__name__, etc.)
    def wrapper(*args, **kwargs):  # Take any arguments
        print(f"Timer: function {func.__name__!r} started.")
        start_time = time.perf_counter()
        result = func(*args, **kwargs)  # Run the wrapped function with it's args
        end_time = time.perf_counter()
        run_time = end_time - start_time
        print(f"Timer: function {func.__name__!r} finished in {run_time:.4f}s.")  # !r explicitly returns as a string with ' '
        return result

    return wrapper


def strip_port(domain):
    '''Strips a port number if present in a domain (e.g. example.com:853 > example.com).'''
    if ":" in domain:
        return domain.split(":")[0]
    else:
        return domain


def get_wiki_content():
    '''Get the Wiki content MD in text format using a basic urllib request.'''
    with urllib.request.urlopen('https://raw.githubusercontent.com/wiki/curl/curl/DNS-over-HTTPS.md') as response:
        return response.read().decode('utf-8')


@timer
def get_domains():
    '''Extract the DoH domains from the Curl Wiki page.'''
    # Retrieve the wiki content, narrow down the response to the public DoH table.
    content = get_wiki_content()
    start = content.find("# Publicly available servers")
    end = content.find("# Private DNS Server")
    public_doh_table = content[start:end]
    lines = public_doh_table.split('\n')

    # Find all of the domains listed in the table.
    domains = []
    for line in lines:
        # Split the line into columns based on md table formatting ('|')
        columns = line.split('|')

        # If the line has at least 3 columns (indicating it's a row in the table and not a header or divider)
        if len(columns) >= 3:
            # Extract the 'Base URL' column
            base_url_column = columns[2]

            # Find all URLs in the column
            column_urls = re.findall(r'https?://[^\s<>"]+', base_url_column)

            # Convert each URL to a domain and append to domains if it isn't a duplicate
            for url in column_urls:
                domain = strip_port(urlparse(url).netloc)
                if len(domain) > 0 and not domain in domains:
                    domains.append(domain)
    return domains


@timer
def resolve_domains(domains):
    '''Resolve each domain to a list of IP addresses for the server.'''
    ips_dict = {}
    ips_flat = []
    for domain in domains:
        try:
            # Get the full list of possible IPs for the domain.
            domain_ips = socket.gethostbyname_ex(domain)[2]
            ips_dict[domain] = domain_ips
            ips_flat.extend(domain_ips)
        except socket.gaierror:
            ips_dict[domain] = []
    return ips_dict, ips_flat


def main():
    domains = get_domains()
    ips_dict, ips_flat = resolve_domains(domains)

    # Write flat domains to txt file.
    with open('domains.txt', 'w') as file:
        for i in range(len(domains)):
            file.write(domains[i])
            if i != len(domains) - 1:
                file.write('\n')

    # Write flat ips to txt file.
    with open('ips.txt', 'w') as file:
        for i in range(len(ips_flat)):
            file.write(ips_flat[i])
            if i != len(ips_flat) - 1:
                file.write('\n')

    # Write domain:[ip,] pairs to json file.
    with open('domain_ips.json', 'w') as file:
        file.write(json.dumps(ips_dict, indent="    "))


if __name__ == '__main__':
    main()
