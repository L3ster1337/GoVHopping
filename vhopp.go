package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device      = "eth0"
	snapLen     = int32(1600)
	promiscuous = false
	timeout     = pcap.BlockForever
	srcMAC, _   = net.ParseMAC("00:01:02:03:04:05")
	dstMAC, _   = net.ParseMAC("ff:ff:ff:ff:ff:ff") // Broadcast MAC Address
	outputFile  = "vlanHoppingLog.txt"
)

// DiscoverVLANs sends packets to discover active VLANs
func DiscoverVLANs(handle *pcap.Handle) {
	for vlanID := 1; vlanID <= 4094; vlanID++ {
		ethLayer := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeDot1Q,
		}
		vlanLayer := &layers.Dot1Q{
			VLANIdentifier: uint16(vlanID),
			Type:           layers.EthernetTypeIPv4,
		}
		ipLayer := &layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    net.IP{10, 0, 0, 1},
			DstIP:    net.IP{10, 0, 0, 2}, // A hypothetical IP, adjust as necessary
			Protocol: layers.IPProtocolTCP,
		}
		tcpLayer := &layers.TCP{
			SrcPort: layers.TCPPort(12345),
			DstPort: layers.TCPPort(80),
		}

		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		gopacket.SerializeLayers(buffer, opts, ethLayer, vlanLayer, ipLayer, tcpLayer)
		outgoingPacket := buffer.Bytes()

		err := handle.WritePacketData(outgoingPacket)
		if err != nil {
			log.Printf("Error sending packet for VLAN ID %d: %v\n", vlanID, err)
		}
		time.Sleep(100 * time.Millisecond) // Sleep to prevent packet loss
	}
}

// CapturePackets captures packets and analyzes them to determine successful hops
func CapturePackets(handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Let's attempt to cast the packet to Ethernet layer and then examine VLAN and IP layers.
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			if eth.EthernetType == layers.EthernetTypeDot1Q {
				vlanLayer := packet.Layer(layers.LayerTypeDot1Q)
				if vlanLayer != nil {
					vlan, _ := vlanLayer.(*layers.Dot1Q)
					fmt.Printf("Received packet on VLAN: %d\n", vlan.VLANIdentifier)
					LogResults(vlan.VLANIdentifier, true) // Assuming receipt is indicative of success
				}
			}
		}
	}
}

// LogResults writes the results of the VLAN hopping to a file
func LogResults(vlanID uint16, success bool) {
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Failed to open log file:", err)
		return
	}
	defer f.Close()

	_, err = f.WriteString(fmt.Sprintf("VLAN ID: %d, Hopping Success: %t\n", vlanID, success))
	if err != nil {
		log.Println("Failed to write to log file:", err)
	}
}

func main() {
	handle, err := pcap.OpenLive(device, snapLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Run VLAN discovery in a separate goroutine
	go DiscoverVLANs(handle)

	// Start packet capture and analysis
	CapturePackets(handle)
}
