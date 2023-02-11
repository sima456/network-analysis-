import requests
import json
import time                                           import pyshark                                        from ipaddress import ip_address
import argparse                                       
def filter_packets(file_path, disp_filter):               # capture only interesting traffic                    capture = pyshark.FileCapture(file_path, display_filter=disp_filter)                                        return capture
                                                      def dns(file_path):
    # this list will store all domain names in the dns packets                                                  resource_list = []
                                                          # filters only dns packets                            packets = filter_packets(file_path, "dns")
    for pkt in packets:
        # if the packet contains a query
        if pkt.dns.qry_name:
            resource_list.append(pkt.dns.qry_name)
    packets.close()
    return resource_list

def ip(file_path):
    # this list will store all IP addresses except the private ones
    resource_list = []

    # filters only IP packets
    packets = filter_packets(file_path, "ip")
    for pkt in packets:
        if pkt.ip:
            src_ip=ip_address(pkt.ip.src)

            # check if it is a private ip or not
            if not src_ip.is_private:
                resource_list.append(pkt.ip.src)
    packets.close()
    return resource_list

def tls(file_path):
    # this list will store server names from TLS client hello
    resource_list = []
    # only TLS client hello packet, no QUICK protocol which uses UDP
    packets = filter_packets(file_path, "tls.handshake.type == 1 and tcp")

    for pkt in packets:
        if pkt.tls.handshake_extensions_server_name:
            resource_list.append(pkt.tls.handshake_extensions_server_name)
    packets.close()
    return resource_list

def http(file_path):
    # this list will store URLS from http and https packets
    resource_list = []
    # only requests like get, post, delete, put, trace, option
    # no SSDP, only http methods
    packets = filter_packets(file_path, "http.request.method and tcp")

    for pkt in packets:
        if pkt.http.request_full_uri:
            resource_list.append(pkt.http.request_full_uri)
    packets.close()
    return resource_list

def https(file_path):
    # this list will store URLS from http and https packets
    resource_list = []
    # only requests like get, post, delete, put, trace, option
    # no SSDP, only http methods
    packets = filter_packets(file_path, "http.request.method and tcp and ssl")

    for pkt in packets:
        if pkt.http.request_full_uri:
            resource_list.append(pkt.http.request_full_uri)
    packets.close()
    return resource_list

def ask_virustotal(resource_list):
    # this key will authorize our requests
    api_key = "465a6ec6d05f0d5c7e6b73f84c36e7f4e4a7ea7e63c294958585564e2ede6e57"

    for malicious_resource in resource_list:
        # VirusTotal API endpoint
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': api_key, 'resource': malicious_resource}
        response = requests.get(url, params=params)
        response_json = json.loads(response.content)

        # if the resource is malicious then it will list which antivirus vendor has marked it.
        try:
            if response_json['positives'] > 0:
                antivir_list = []

                for antivir in response_json['scans']:
                    if response_json['scans'][antivir]['detected'] == True:
                        antivir_list.append(antivir)
                print(response_json['resource'])
                print("The resource above is found malicious by", antivir_list)
        except:
            pass

        # since we are using a free version, we can make not more than 4 requests per minute
        # we will limit that by making the script sleep for 16 seconds after each request
        time.sleep(16)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Process a PCAP file and search for malicious resources.')
    parser.add_argument('file_path', help='Path to the PCAP file')
    args = parser.parse_args()

    file_path = args.file_path

    dns_resources = dns(file_path)
    ip_resources = ip(file_path)
    tls_resources = tls(file_path)
    http_resources = http(file_path)

    ask_virustotal(dns_resources)
    ask_virustotal(ip_resources)
    ask_virustotal(tls_resources)
    ask_virustotal(http_resources)
