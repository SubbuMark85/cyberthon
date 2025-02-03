import socket
import ssl
import nmap
import requests
import whois
import re
from datetime import datetime
from dateutil import parser

def is_valid_domain(domain):
    """ Validate domain name """
    pattern = re.compile(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$")
    return bool(pattern.match(domain))

def get_ip(domain):
    """ Get IP address of the domain """
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def scan_ports(domain):
    """ Scan open ports and detect running services """
    ip = get_ip(domain)
    if not ip:
        print(f"Unable to resolve IP for {domain}")
        return None
    
    print(f"\n🔍 Scanning {domain} ({ip})...\n")
    
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-sV')  # -sV detects service versions
    
    results = []
    for host in scanner.all_hosts():
        for port in scanner[host]['tcp']:
            service = scanner[host]['tcp'][port]
            results.append({
                "port": port,
                "state": service['state'],
                "name": service['name'],
                "version": service.get('version', 'Unknown')
            })
    
    return results

def check_security_headers(domain):
    """ Check website security headers """
    try:
        url = f"https://{domain}"
        response = requests.get(url, timeout=5)
    except requests.exceptions.SSLError:
        url = f"http://{domain}"
        response = requests.get(url, timeout=5)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {domain}: {e}")
        return None
    
    headers = response.headers
    security_headers = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-XSS-Protection", "X-Content-Type-Options"
    ]
    
    missing_headers = [h for h in security_headers if h not in headers]
    return missing_headers

def check_ssl_certificate(domain):
    """ Check SSL/TLS certificate details """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        
        expiry_date = parser.parse(cert['notAfter'])
        issuer = dict(x[0] for x in cert['issuer'])
        
        return {
            "issuer": issuer.get("organizationName", "Unknown"),
            "expiry_date": expiry_date.strftime("%Y-%m-%d"),
            "valid": expiry_date > datetime.now()
        }
    except Exception as e:
        print(f"Error checking SSL certificate: {e}")
        return None

def get_domain_info(domain):
    """ Fetch domain WHOIS info """
    try:
        domain_info = whois.whois(domain)
        return {
            "registrar": domain_info.registrar if domain_info.registrar else "Unknown",
            "creation_date": domain_info.creation_date.strftime("%Y-%m-%d") if domain_info.creation_date else "Unknown",
            "expiration_date": domain_info.expiration_date.strftime("%Y-%m-%d") if domain_info.expiration_date else "Unknown"
        }
    except Exception as e:
        print(f"Error fetching WHOIS info: {e}")
        return None

# Prompt user to input the website to scan
website = input("Enter the website to scan (e.g., example.com): ").strip()
if not is_valid_domain(website):
    print("Invalid domain name. Please try again.")
    exit(1)

# Perform the scans
port_results = scan_ports(website)
security_results = check_security_headers(website)
ssl_results = check_ssl_certificate(website)
whois_results = get_domain_info(website)

# Print results
if port_results:
    print("\n✅ Open Ports and Services:")
    for res in port_results:
        print(f"  - Port {res['port']} ({res['name']}): {res['version']} [{res['state']}]")

if security_results is not None:
    if security_results:
        print("\n⚠ Missing Security Headers:")
        for header in security_results:
            print(f"  - {header}")
    else:
        print("\n✅ All critical security headers are present.")

if ssl_results:
    print(f"\n🔐 SSL Certificate Info:")
    print(f"  - Issuer: {ssl_results['issuer']}")
    print(f"  - Expiry Date: {ssl_results['expiry_date']}")
    print(f"  - Status: {'Valid' if ssl_results['valid'] else 'Expired'}")

if whois_results:
    print("\n🌐 Domain WHOIS Info:")
    print(f"  - Registrar: {whois_results['registrar']}")
    print(f"  - Created On: {whois_results['creation_date']}")
    print(f"  - Expires On: {whois_results['expiration_date']}")

print("\n✅ Website security check complete.")