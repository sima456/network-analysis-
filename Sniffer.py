import pyshark
import requests

# Step-1: Importing required Python modules
import pyshark # for capturing packets
import requests # for making API calls to VirusTotal

# Step-2: Creating a display filter for interesting traffic
# Let's assume we want to capture DNS, HTTP, and HTTPS traffic
display_filter = "dns or http or ssl"

# Step-3: Creating a function for extracting DNS resource records
def extract_dns_records(packet):
    dns_records = []
    if "DNS" in packet:
        # extract the DNS resource records
        dns_layer = packet.get_layer("DNS")
        dns_records = dns_layer.get_field_value("queries")
    return dns_records

# Step-4: Creating a function that extracts IP addresses from IP headers
def extract_ip_addresses(packet):
    src_ip = packet.ip.src
    dst_ip = packet.ip.dst
    return src_ip, dst_ip

# Step-5: Creating a function that extracts Server Names from TLS client hello packets
def extract_tls_server_name(packet):
    server_name = None
    if "TLS" in packet and hasattr(packet.ssl, "handshake_extensions_server_name"):
        server_name = packet.ssl.handshake_extensions_server_name
    return server_name

# Step-6: Creating a function that extracts URLs from http/https packets
def extract_http_url(packet):
    url = None
    if "HTTP" in packet:
        # extract the request URL
        http_layer = packet.get_layer("HTTP")
        url = http_layer.request_full_uri
    return url

# Step-7: Creating a function that uses Virustotal’s API to detect the malicious resources
def check_malicious(resource):
    api_key = "b21081b363d985cb0e9100cce9f90d36d93bbf2e060afb8"
    url = f"https://www.virustotal.com/api/v3/urls/{resource}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    response_json = response.json()
    return response_json

# Capture the packets using pyshark
capture = pyshark.LiveCapture(interface="eth0", display_filter=display_filter)

# Iterate over each packet and extract the required information
for packet in capture.sniff_continuously():
    dns_records = extract_dns_records(packet)
    src_ip, dst_ip = extract_ip_addresses(packet)
    server_name = extract_tls_server_name(packet)
    url = extract_http_url(packet)

    # check if the resource is malicious using VirusTotal's API
    if url:
        result = check_malicious(url)
        if result["data"]["attributes"]["last_analysis_results"]["result"] == "malicious":
            print(f"Found")
