package main

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
)

func vlanHop(vlanID uint16) {
	// Definindo a interface de rede
	ifaceName := "eth0"

	// Abertura do dispositivo de captura
	handle, err := pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	// Filtro para pacotes VLAN
	filter := fmt.Sprintf("vlan and vlan %d", vlanID)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	// Criação do pacote ARP
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		SourceProtAddress: net.IP{192, 168, 0, 1},
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    net.IP{192, 168, 0, 2},
	}

	// Criação do pacote Ethernet
	ethernet := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeDot1Q,
	}

	// Criação do pacote VLAN com o ID especificado
	vlan := layers.Dot1Q{
		VLANIdentifier: vlanID,
		Type:           layers.EthernetTypeARP,
	}

	// Concatenação dos pacotes
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err = gopacket.SerializeLayers(buffer, opts,
		&ethernet,
		&vlan,
		&arp,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Envio do pacote
	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	// Fechamento do dispositivo de captura
	handle.Close()
}

func main() {
	// Exemplo de uso
	vlanHop(10)
}
