import pyshark
import time

# define file path
file_path = "2017-07-22-traffic-analysis-exercise.pcap"

# define capture object
capture = pyshark.FileCapture(file_path)

print("reading from file: %s" % file_path)

for packet in capture:
    # adjusted output
    try:
        # get packet timestamp
        packet_timestamp = packet.sniff_time
        localtime = time.asctime(time.localtime(packet_timestamp.timestamp()))

        # get packet content
        protocol = packet.transport_layer   # protocol type
        src_addr = packet.ip.src            # source address
        src_port = packet[protocol].srcport   # source port
        dst_addr = packet.ip.dst            # destination address
        dst_port = packet[protocol].dstport   # destination port

        # output packet info
        print ("%s IP %s:%s <-> %s:%s (%s)" % (localtime, src_addr, src_port, dst_addr, dst_port, protocol))
    except AttributeError as e:
        # ignore packets other than TCP, UDP and IPv4
        pass
    print (" ")
