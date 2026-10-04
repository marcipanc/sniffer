Traffic sniffer. Version 0.1

Description:
This application is a simple sniffer designed to capture and write Internet packets.

Requirements:
* Python version greater than 3.12


Composition:
* Console version: csniffer.py
* Logic: src/
* Tests: tests/
  You can execute all tests in one go using the runtests.sh 


Console version
Launch help: sudo ./csniffer.py --help
Launch example: sudo ./csniffer.py -c 10 -o out.pcap

Note: This program requires root privileges because it uses raw sockets
