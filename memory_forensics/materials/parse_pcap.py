#!/usr/bin/env python3

import sys
import pathlib
import dpkt
from dpkt.utils import inet_to_str


def extract_flag(pcap):
    """Extract flag from pcap
    Args:
        pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    flag = b""
    # For each packet in the pcap process the contents
    for _, buf in pcap:

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        # Now access the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        # Skip packets not directed towards the attacker's machine
        if inet_to_str(ip.dst) != "":
            continue

        # Set the TCP data
        tcp = ip.data

        # We know exfiltration uses port ???
        if tcp.sport != -1 or tcp.dport != -1:
            continue

        # Undo the obfuscation
        pass

    print(flag.decode("ASCII"))


def main():
    capture = pathlib.Path(sys.argv[1])
    with capture.open(mode="rb") as f:
        pcap = dpkt.pcap.Reader(f)
        extract_flag(pcap)


if __name__ == "__main__":
    main()
