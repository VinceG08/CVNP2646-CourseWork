# Network Traffic Monitor

A Python tool that analyzes network logs to detect port scans and SYN flood attacks.

---

## Usage

```bash
python network_monitor.py traffic_sample.log
```

Optional:

```bash
python network_monitor.py traffic_sample.log -o results.json -p 30 -s 120
```

---

## Features

* Detects port scans (based on unique ports)
* Detects SYN floods (based on SYN packet count)
* Uses logging instead of print statements
* Command-line interface with argparse
* Includes pytest tests

---

## Project Files

```
network_monitor.py
test_network_monitor.py
traffic_sample.log
README.md
```

---

## Improvements Made

* Removed global variables
* Replaced magic numbers with configuration
* Split code into small functions
* Separated file I/O from logic
* Added error handling
* Added tests