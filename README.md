# VLAN Hopping Tool
<p align="center">
  <img src="bunnyy.jpeg">
  <br>
  <i>"Ruuun Forest, ruuuun" - Curran, Jenny</i>
</p>


## Overview

This VLAN Hopping tool is developed in Go and utilizes the `gopacket` library to craft and send packets for VLAN hopping attacks. It specifically creates and sends an ARP request encapsulated within a VLAN tagged frame to demonstrate how an attacker might hop from one VLAN to another. This tool is intended for educational purposes and network security testing within environments where you have explicit permission to test.
<br>
<br>
<b>--->Education purposes only, do not test it in airports, c'mon <--- </b>
## Features

- Craft ARP requests encapsulated in VLAN tagged frames.
- Specify target VLAN ID for hopping.
- Utilize raw sockets to send crafted packets.
- Network interface selection for packet sending.

## Requirements

- Go programming language
- `libpcap` library
- `gopacket` Go library

## Installation

Before you can run this tool, ensure you have Go installed on your system along with the `libpcap` development package which is required by the `gopacket` library.

1. Install Go (if not installed): Visit [Go's official installation guide](https://golang.org/doc/install).
2. Install `libpcap` development package:
   - On Debian-based systems: `sudo apt-get install libpcap-dev`
   - On Red Hat-based systems: `sudo yum install libpcap-devel`
   - On macOS: `libpcap` is usually pre-installed, or you can use Homebrew: `brew install libpcap`
3. Clone this repository:
   ```
  
   ```
If there's any error, please contact me :)
