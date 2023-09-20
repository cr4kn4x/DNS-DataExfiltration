# DNS-DataExfiltration

## Description

This implementation is inspired by the PyExfil Project (Copyright (c) 2014 Yuval tisf Nativ, Link: https://github.com/ytisf/PyExfil)

In this repository, you will find a Python3 implementation of my Data-Exfiltration approach to bypass Firewalls for e.g. File-Transfers. This piece of code can be used for penetration testing !only! on your own devices!

Just study the code and you will understand the features this implementation provides for you. Most imporant features are: 

- [X] Fast & reliable encryption using SALSA20
- [X] Integrity Protection / Fail safe transfer by using CRC32
- [X] Adjustable Packet Size & Sending Interval
- [X] No malformed DNS requests

 

## Prerequisites

Make sure Python3 is installed on your System.

1. Clone this repository

  ```console
  git clone https://github.com/cr4kn4x/DNS-DataExfiltration.git
  ```

3. Open the folder of the cloned repository in your shell

  ```console
  cd DNS-DataExfiltration
  ```

2. Initialize Python virtual environment

  ```console
  python python -m venv ./
  ```

 3. Activate virtual environment
  
  ```console
  .\Scripts\Activate.ps1
  ```

  4. Install requirements
  
  ```console
  pip install -r requirements.txt
  ```

  5. Run DNS-Exfiltration Server
  ```console
  python Server/main.py
  ```

  6. Run DNS-Exfiltration Client
  ```console
  python Client/main.py
  ```

