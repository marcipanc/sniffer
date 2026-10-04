# Traffic Sniffer v0.1

A CLI application designed to capture network traffic and save it in PCAP format

## Requirements and Privileges

* Python 3.12 or higher.
* Root privileges (sudo) are required because the application utilizes raw sockets for packet capture

## Project Structure

* `csniffer.py` — Main console application entry point.
* `src/` — Core logic and packet encoding.
* `tests/` — Test suites. Run all tests simultaneously using ./runtests.sh

## Usage Examples

View all available options and flags:
```bash
sudo ./csniffer.py --help
```

Capture 10 packets and save them to a file:
```bash
sudo ./csniffer.py -c 10 -o out.pcap
```

Capture packets until keyboard interrupt in verbose mode:
```bash
sudo ./csniffer.py -v
```
