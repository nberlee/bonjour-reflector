package main

import (
	"bytes"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	srcMACTest          = net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA}
	dstMACTest          = net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD}
	brMACTest           = net.HardwareAddr{0xF2, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA}
	vlanIdentifierTest  = uint16(30)
	srcIPv4Test         = net.IP{127, 0, 0, 1}
	dstIPv4Test         = net.IP{224, 0, 0, 251}
	srcIPv6Test         = net.ParseIP("::1")
	dstIPv6Test         = net.ParseIP("ff02::fb")
	srcUDPPortTest      = layers.UDPPort(5353)
	dstUDPPortTest      = layers.UDPPort(5353)
	questionPayloadTest = []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97,
		109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1}
)

func createMockmDNSPacket(isIPv4 bool, isDNSQuery bool) []byte {
	if isIPv4 {
		return createRawPacket(isIPv4, isDNSQuery, vlanIdentifierTest, dstIPv4Test, srcMACTest, dstMACTest, dstUDPPortTest)
	}
	return createRawPacket(isIPv4, isDNSQuery, vlanIdentifierTest, dstIPv6Test, srcMACTest, dstMACTest, dstUDPPortTest)
}

func createRawPacket(isIPv4 bool, isDNSQuery bool, vlanTag uint16, dstIP net.IP, srcMAC net.HardwareAddr, dstMAC net.HardwareAddr, dstPort layers.UDPPort) []byte {
	var ethernetLayer, dot1QLayer, ipLayer, udpLayer, dnsLayer gopacket.SerializableLayer

	ethernetLayer = &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeDot1Q,
	}

	if isIPv4 {
		dot1QLayer = &layers.Dot1Q{
			VLANIdentifier: vlanTag,
			Type:           layers.EthernetTypeIPv4,
		}

		ipLayer = &layers.IPv4{
			SrcIP:    srcIPv4Test,
			DstIP:    dstIP,
			Version:  4,
			Protocol: layers.IPProtocolUDP,
			Length:   146,
			IHL:      5,
			TOS:      0,
		}
	} else {
		dot1QLayer = &layers.Dot1Q{
			VLANIdentifier: vlanTag,
			Type:           layers.EthernetTypeIPv6,
		}

		ipLayer = &layers.IPv6{
			SrcIP:      srcIPv6Test,
			DstIP:      dstIP,
			Version:    6,
			Length:     48,
			NextHeader: layers.IPProtocolUDP,
		}
	}

	udpLayer = &layers.UDP{
		SrcPort: srcUDPPortTest,
		DstPort: dstPort,
	}

	if isDNSQuery {
		dnsLayer = &layers.DNS{
			Questions: []layers.DNSQuestion{layers.DNSQuestion{
				Name:  []byte("example.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			}},
			QDCount: 1,
		}
	} else {
		dnsLayer = &layers.DNS{
			Answers: []layers.DNSResourceRecord{layers.DNSResourceRecord{
				Name:  []byte("example.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   1024,
				IP:    net.IP([]byte{1, 2, 3, 4}),
			}},
			ANCount: 1,
			QR:      true,
		}
	}

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{},
		ethernetLayer,
		dot1QLayer,
		ipLayer,
		udpLayer,
		dnsLayer,
	)
	return buffer.Bytes()
}

func TestParseEthernetLayer(t *testing.T) {
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	options := gopacket.DecodeOptions{Lazy: true}

	packet := gopacket.NewPacket(createMockmDNSPacket(true, true), decoder, options)

	expectedResult1, expectedResult2 := &srcMACTest, &dstMACTest
	computedResult1, computedResult2 := parseEthernetLayer(packet)
	if !reflect.DeepEqual(expectedResult1, computedResult1) || !reflect.DeepEqual(expectedResult2, computedResult2) {
		t.Error("Error in parseEthernetLayer()")
	}
}

func TestParseVLANTag(t *testing.T) {
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	options := gopacket.DecodeOptions{Lazy: true}

	packet := gopacket.NewPacket(createMockmDNSPacket(true, true), decoder, options)

	expectedLayer := &layers.Dot1Q{
		VLANIdentifier: vlanIdentifierTest,
		Type:           layers.EthernetTypeIPv4,
	}
	expectedResult := &expectedLayer.VLANIdentifier
	computedResult := parseVLANTag(packet)
	if !reflect.DeepEqual(expectedResult, computedResult) {
		t.Error("Error in parseEthernetLayer()")
	}
}

func TestParseIPLayer(t *testing.T) {
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	options := gopacket.DecodeOptions{Lazy: true}

	isIPv4 := true
	ipv4Packet := gopacket.NewPacket(createMockmDNSPacket(isIPv4, true), decoder, options)

	computedIsIPv6, _, _ := parseIPLayer(ipv4Packet)
	if computedIsIPv6 == true {
		t.Error("Error in parseIPLayer() for IPv4 addresses")
	}

	isIPv4 = false
	ipv6Packet := gopacket.NewPacket(createMockmDNSPacket(isIPv4, true), decoder, options)

	computedIsIPv6, _, _ = parseIPLayer(ipv6Packet)
	if computedIsIPv6 == false {
		t.Error("Error in parseIPLayer() for IPv6 addresses")
	}
}

func TestParseUDPLayer(t *testing.T) {
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	options := gopacket.DecodeOptions{Lazy: true}

	packet := gopacket.NewPacket(createMockmDNSPacket(true, true), decoder, options)

	questionPacketPayload, _, _ := parseUDPLayer(packet)
	if !reflect.DeepEqual(questionPayloadTest, questionPacketPayload) {
		t.Error("Error in parseUDPLayer()")
	}
}

func TestParseDNSPayload(t *testing.T) {
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	options := gopacket.DecodeOptions{Lazy: true}

	questionPacket := gopacket.NewPacket(createMockmDNSPacket(true, true), decoder, options)

	questionPacketPayload, _, _ := parseUDPLayer(questionPacket)

	questionExpectedResult := true
	questionComputedResult, _ := parseDNSPayload(questionPacketPayload)
	if !reflect.DeepEqual(questionExpectedResult, questionComputedResult) {
		t.Error("Error in parseDNSPayload() for DNS queries")
	}

	answerPacket := gopacket.NewPacket(createMockmDNSPacket(true, false), decoder, options)

	answerPacketPayload, _, _ := parseUDPLayer(answerPacket)

	answerExpectedResult := false
	answerComputedResult, _ := parseDNSPayload(answerPacketPayload)
	if !reflect.DeepEqual(answerExpectedResult, answerComputedResult) {
		t.Error("Error in parseDNSPayload() for DNS answers")
	}
}

type dataSource struct {
	sentPackets int
	data        [][]byte
}

func (dataSource *dataSource) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	// Return one packet for each call.
	// If all the expected packets have already been returned in the past, return an EOF error
	// to end the reading of packets from this source.
	if dataSource.sentPackets >= len(dataSource.data) {
		return nil, ci, io.EOF
	}
	data = dataSource.data[dataSource.sentPackets]
	ci = gopacket.CaptureInfo{
		Timestamp:      time.Time{},
		CaptureLength:  len(data),
		Length:         ci.CaptureLength,
		InterfaceIndex: 0,
	}
	dataSource.sentPackets++
	return data, ci, nil
}

func createMockPacketSource() (packetSource *gopacket.PacketSource, packet gopacket.Packet) {
	// send one legitimate packet
	// Return the packetSource and the legitimate packet
	data := [][]byte{
		createMockmDNSPacket(true, true)}
	dataSource := &dataSource{
		sentPackets: 0,
		data:        data,
	}
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	packetSource = gopacket.NewPacketSource(dataSource, decoder)
	packet = gopacket.NewPacket(data[len(data)-1], decoder, gopacket.DecodeOptions{Lazy: true})
	return
}

func areBonjourPacketsEqual(a, b multicastPacket) (areEqual bool) {
	areEqual = (*a.vlanTag == *b.vlanTag) && (a.srcMAC.String() == b.srcMAC.String()) && (a.isDNSQuery == b.isDNSQuery)
	// While comparing Bonjour packets, we do not want to compare packets entirely.
	// In particular, packet.metadata may be slightly different, we do not need them to be the same.
	// So we only compare the layers part of the packets.
	areEqual = areEqual && reflect.DeepEqual(a.packet.Layers(), b.packet.Layers())
	return
}

func TestFilterBonjourPacketsLazily(t *testing.T) {
	mockPacketSource, packet := createMockPacketSource()
	packetChan := parsePacketsLazily(mockPacketSource)

	expectedResult := multicastPacket{
		packet:     packet,
		vlanTag:    &vlanIdentifierTest,
		srcMAC:     &srcMACTest,
		isDNSQuery: true,
	}

	computedResult := <-packetChan
	if !areBonjourPacketsEqual(expectedResult, computedResult) {
		t.Error("Error in parsePacketsLazily()")
	}
}

type mockPacketWriter struct {
	packet gopacket.Packet
}

func (pw *mockPacketWriter) WritePacketData(bytes []byte) (err error) {
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	pw.packet = gopacket.NewPacket(bytes, decoder, gopacket.DecodeOptions{Lazy: true})
	return
}

func TestSendBonjourPacket(t *testing.T) {
	// Craft a test packet
	initialDataIPv4 := createMockmDNSPacket(true, true)
	initialDataIPv6 := createMockmDNSPacket(false, true)
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	initialPacketIPv4 := gopacket.NewPacket(initialDataIPv4, decoder, gopacket.DecodeOptions{Lazy: true})
	initialPacketIPv6 := gopacket.NewPacket(initialDataIPv6, decoder, gopacket.DecodeOptions{Lazy: true})

	srcMACv4, dstMACv4 := parseEthernetLayer(initialPacketIPv4)
	bonjourTestPacketIPv4 := multicastPacket{
		packet:     initialPacketIPv4,
		vlanTag:    parseVLANTag(initialPacketIPv4),
		srcMAC:     srcMACv4,
		dstMAC:     dstMACv4,
		srcIP:      &srcIPv4Test,
		dstIP:      &dstIPv4Test,
		isDNSQuery: true,
		isIPv6:     false,
	}

	srcMACv6, dstMACv6 := parseEthernetLayer(initialPacketIPv6)
	bonjourTestPacketIPv6 := multicastPacket{
		packet:     initialPacketIPv6,
		vlanTag:    parseVLANTag(initialPacketIPv6),
		srcMAC:     srcMACv6,
		dstMAC:     dstMACv6,
		srcIP:      &srcIPv6Test,
		dstIP:      &dstIPv6Test,
		isDNSQuery: true,
		isIPv6:     true,
	}

	newVlanTag := uint16(29)

	expectedDstMACv4 := net.HardwareAddr{0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB}
	expectedDataIPv4 := createRawPacket(true, true, newVlanTag, dstIPv4Test, brMACTest, expectedDstMACv4, dstUDPPortTest)
	expectedPacketIPv4 := gopacket.NewPacket(expectedDataIPv4, decoder, gopacket.DecodeOptions{Lazy: true})

	expectedDstMACv6 := net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0xFB}
	expectedDataIPv6 := createRawPacket(false, true, newVlanTag, dstIPv6Test, brMACTest, expectedDstMACv6, dstUDPPortTest)
	expectedPacketIPv6 := gopacket.NewPacket(expectedDataIPv6, decoder, gopacket.DecodeOptions{Lazy: true})

	pw := &mockPacketWriter{packet: nil}

	sendPacket(pw, &bonjourTestPacketIPv4, newVlanTag, srcMACTest, dstMACTest, srcIPv4Test, dstIPv4Test)
	if !cmpPacket(expectedPacketIPv4.Layers(), pw.packet.Layers()) {
		t.Error("Error in sendBonjourPacket() for IPv4")
	}

	sendPacket(pw, &bonjourTestPacketIPv6, newVlanTag, srcMACTest, dstMACTest, srcIPv6Test, dstIPv6Test)
	if !cmpPacket(expectedPacketIPv6.Layers(), pw.packet.Layers()) {
		t.Error("Error in sendBonjourPacket() for IPv6")
	}
}

// We cannot compare slices of packet layers directly, so we compare the payload of the UDP layer instead.
func cmpPacket(a, b []gopacket.Layer) bool {
	udpLayer := 3
	if len(a) < udpLayer || len(b) < udpLayer {
		return false
	}

	aBytes := a[udpLayer].(*layers.UDP).Payload
	bBytes := b[udpLayer].(*layers.UDP).Payload
	return bytes.Equal(aBytes, bBytes)
}
