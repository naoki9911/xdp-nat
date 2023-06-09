package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/olekukonko/tablewriter"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp/xdp.c -- -I./xdp/headers

/*
#include <time.h>
static unsigned long long get_nsecs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000UL + ts.tv_nsec;
}
*/
import "C"

type V4TupleC struct {
	Addr    uint32
	Port    uint16
	Padding uint16
}

type V4Tuple struct {
	Addr net.IP
	Port uint16
}

func Uint32ToIPv4(a uint32) net.IP {
	return net.IPv4(byte(a), byte(a>>8), byte(a>>16), byte(a>>24))
}

func IPv4ToUint32(a net.IP) uint32 {
	ip4 := a.To4()
	return uint32(ip4[0]) | (uint32(ip4[1]) << 8) | (uint32(ip4[2]) << 16) | (uint32(ip4[3]) << 24)
}

func (v V4TupleC) ToGo() V4Tuple {
	res := V4Tuple{
		Port: v.Port,
	}
	res.Addr = Uint32ToIPv4(v.Addr)

	return res
}

type V4CTC struct {
	InnerSrcMAC [6]byte
	InnerDstMAC [6]byte
	OuterSrcMAC [6]byte
	OuterDstMAC [6]byte
	InnerAddr   uint32
	OuterAddr   uint32
	EndAddr     uint32
	InnerPort   uint16
	OuterPort   uint16
	EndPort     uint16
	Type        uint16
	Padding     uint32
	KTime       uint64
	PktCount    uint64
	OctCount    uint64
}

type V4CT struct {
	InnerSrcMAC net.HardwareAddr
	InnerDstMAC net.HardwareAddr
	OuterSrcMAC net.HardwareAddr
	OuterDstMAC net.HardwareAddr
	InnerAddr   net.IP
	OuterAddr   net.IP
	EndAddr     net.IP
	InnerPort   uint16
	OuterPort   uint16
	EndPort     uint16
	Type        uint16
	KTime       int64
	PktCount    uint64
	OctCount    uint64
}

func (v V4CTC) ToGo() V4CT {
	res := V4CT{
		InnerSrcMAC: v.InnerSrcMAC[0:],
		InnerDstMAC: v.InnerDstMAC[0:],
		OuterSrcMAC: v.OuterSrcMAC[0:],
		OuterDstMAC: v.OuterDstMAC[0:],
		InnerPort:   v.InnerPort,
		OuterPort:   v.OuterPort,
		EndPort:     v.EndPort,
		KTime:       int64(v.KTime),
		Type:        v.Type,
		PktCount:    v.PktCount,
		OctCount:    v.OctCount,
	}

	res.InnerAddr = Uint32ToIPv4(v.InnerAddr)
	res.OuterAddr = Uint32ToIPv4(v.OuterAddr)
	res.EndAddr = Uint32ToIPv4(v.EndAddr)

	return res
}

type ConfigC struct {
	InnerIfIndex uint16
	OuterIfIndex uint16
	InnerAddr    uint32
	OuterAddr    uint32
}

type Metric struct {
	Protocol                string
	InnerAddr               net.IP
	InnerPort               uint16
	OuterAddr               net.IP
	OuterPort               uint16
	EndpointAddr            net.IP
	EndpointPort            uint16
	Misc                    string
	LastPacketElapsedSecond int
	Inner2OuterPacketCount  uint64
	Inner2OuterOctetCount   uint64
	Outer2InnerPacketCount  uint64
	Outer2InnerOctetCount   uint64
}

func NewMetricFromV4CT(v V4CT) Metric {
	return Metric{
		InnerAddr:              v.InnerAddr,
		InnerPort:              v.InnerPort,
		OuterAddr:              v.OuterAddr,
		OuterPort:              v.OuterPort,
		EndpointAddr:           v.EndAddr,
		EndpointPort:           v.EndPort,
		Inner2OuterPacketCount: v.PktCount,
		Inner2OuterOctetCount:  v.OctCount,
	}
}

func (m Metric) ToStrings() []string {
	res := make([]string, 0)
	res = append(res, m.Protocol)
	res = append(res, fmt.Sprintf("%s:%d", m.InnerAddr, m.InnerPort))
	res = append(res, fmt.Sprintf("%s:%d", m.OuterAddr, m.OuterPort))
	res = append(res, fmt.Sprintf("%s:%d", m.EndpointAddr, m.EndpointPort))
	res = append(res, m.Misc)
	res = append(res, fmt.Sprintf("%d", m.LastPacketElapsedSecond))
	res = append(res, fmt.Sprintf("%d", m.Inner2OuterPacketCount))
	res = append(res, fmt.Sprintf("%d", m.Outer2InnerPacketCount))
	res = append(res, fmt.Sprintf("%d", m.Inner2OuterOctetCount))
	res = append(res, fmt.Sprintf("%d", m.Outer2InnerOctetCount))

	return res
}

const pinBaseDir = "/sys/fs/bpf"

var pinGlobalDir = filepath.Join(pinBaseDir, "global")

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	innerIfName := os.Args[1]
	innerIf, err := net.InterfaceByName(innerIfName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", innerIfName, err)
	}

	outerIfName := os.Args[2]
	outerIf, err := net.InterfaceByName(outerIfName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", outerIfName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	config := ConfigC{
		InnerIfIndex: uint16(innerIf.Index),
		OuterIfIndex: uint16(outerIf.Index),
		InnerAddr:    IPv4ToUint32(net.IPv4(192, 168, 123, 1)),
		OuterAddr:    IPv4ToUint32(net.IPv4(172, 28, 97, 10)),
	}
	err = objs.Configs.Put(uint32(0), config)
	if err != nil {
		log.Fatalf("could not put config: %s", err)
	}

	port_i := uint16(10000)
	for port_i < 10100 {
		err = objs.ReservedPortV4Tcp.Put(nil, port_i)
		if err != nil {
			log.Fatalf("could not put reserved port: %s", err)
		}
		err = objs.ReservedPortV4Udp.Put(nil, port_i)
		if err != nil {
			log.Fatalf("could not put reserved port: %s", err)
		}
		port_i += 1
	}

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpNatInner2outerFunc,
		Interface: innerIf.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	l2, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpNatOuter2innerFunc,
		Interface: outerIf.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l2.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", outerIf.Name, outerIf.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		metrics := map[string]Metric{}
		unix_nano := int64(C.get_nsecs())

		t, err := readNatTable(objs.Inner2outerV4Tcp)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		for kc, vc := range t {
			v := vc.ToGo()
			elapsed_nano := unix_nano - v.KTime
			elapsed_sec := elapsed_nano / (1000 * 1000 * 1000)
			var state int16
			err = objs.StateV4Tcp.Lookup(kc, &state)
			if err != nil {
				log.Printf("Error to get state: %s", err)
				continue
			}
			m_k := fmt.Sprintf("%s:%d=%s:%d:TCP", v.InnerAddr, v.InnerPort, v.OuterAddr, v.OuterPort)
			m := NewMetricFromV4CT(v)
			m.Misc = fmt.Sprintf("State=%d", state)
			m.LastPacketElapsedSecond = int(elapsed_sec)
			m.Protocol = "TCP"
			metrics[m_k] = m
		}

		t, err = readNatTable(objs.Outer2innerV4Tcp)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		for _, vc := range t {
			v := vc.ToGo()
			elapsed_nano := unix_nano - v.KTime
			elapsed_sec := int(elapsed_nano / (1000 * 1000 * 1000))
			m_k := fmt.Sprintf("%s:%d=%s:%d:TCP", v.InnerAddr, v.InnerPort, v.OuterAddr, v.OuterPort)
			m, ok := metrics[m_k]
			if !ok {
				log.Printf("failed to get metric %s", m_k)
			}
			if m.LastPacketElapsedSecond > elapsed_sec {
				m.LastPacketElapsedSecond = elapsed_sec
			}
			m.Outer2InnerPacketCount = v.PktCount
			m.Outer2InnerOctetCount = v.OctCount
			metrics[m_k] = m
		}

		t, err = readNatTable(objs.Inner2outerV4Udp)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		for _, vc := range t {
			v := vc.ToGo()
			elapsed_nano := unix_nano - v.KTime
			elapsed_sec := int(elapsed_nano / (1000 * 1000 * 1000))
			m_k := fmt.Sprintf("%s:%d=%s:%d:UDP", v.InnerAddr, v.InnerPort, v.OuterAddr, v.OuterPort)
			m := NewMetricFromV4CT(v)
			m.Protocol = "UDP"
			m.LastPacketElapsedSecond = int(elapsed_sec)
			metrics[m_k] = m
		}

		t, err = readNatTable(objs.Outer2innerV4Udp)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		for _, vc := range t {
			v := vc.ToGo()
			elapsed_nano := unix_nano - v.KTime
			elapsed_sec := int(elapsed_nano / (1000 * 1000 * 1000))
			m_k := fmt.Sprintf("%s:%d=%s:%d:UDP", v.InnerAddr, v.InnerPort, v.OuterAddr, v.OuterPort)
			m, ok := metrics[m_k]
			if !ok {
				log.Printf("failed to get metric %s", m_k)
			}
			if m.LastPacketElapsedSecond > elapsed_sec {
				m.LastPacketElapsedSecond = elapsed_sec
			}
			m.Outer2InnerPacketCount = v.PktCount
			m.Outer2InnerOctetCount = v.OctCount
			metrics[m_k] = m
		}

		t, err = readNatTable(objs.Inner2outerV4Icmp)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		for _, vc := range t {
			v := vc.ToGo()
			elapsed_nano := unix_nano - v.KTime
			elapsed_sec := int(elapsed_nano / (1000 * 1000 * 1000))
			m_k := fmt.Sprintf("%s:%d=%s:%d:ICMP", v.InnerAddr, v.InnerPort, v.OuterAddr, v.OuterPort)
			m := NewMetricFromV4CT(v)
			m.Protocol = "ICMP"
			m.Misc = fmt.Sprintf("ID=0x%04X", v.InnerPort)
			m.LastPacketElapsedSecond = int(elapsed_sec)
			metrics[m_k] = m
		}

		t, err = readNatTable(objs.Outer2innerV4Icmp)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		for _, vc := range t {
			v := vc.ToGo()
			elapsed_nano := unix_nano - v.KTime
			elapsed_sec := int(elapsed_nano / (1000 * 1000 * 1000))
			m_k := fmt.Sprintf("%s:%d=%s:%d:ICMP", v.InnerAddr, v.InnerPort, v.OuterAddr, v.OuterPort)
			m, ok := metrics[m_k]
			if !ok {
				log.Printf("failed to get metric %s", m_k)
			}
			if m.LastPacketElapsedSecond > elapsed_sec {
				m.LastPacketElapsedSecond = elapsed_sec
			}
			m.Outer2InnerPacketCount = v.PktCount
			m.Outer2InnerOctetCount = v.OctCount
			metrics[m_k] = m
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Protocol", "Inner", "Outer", "Endpoint", "Misc", "Elapsed(sec)", "I2O Packet", "O2I Packet", "I2O bytes", "O2I bytes"})
		keys := []string{}
		for k := range metrics {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			table.Append(metrics[k].ToStrings())
		}
		table.Render()

		for _, v := range metrics {
			if v.LastPacketElapsedSecond < 10 {
				continue
			}
			tInner := V4TupleC{
				Addr: IPv4ToUint32(v.InnerAddr),
				Port: v.InnerPort,
			}
			tOuter := V4TupleC{
				Addr: IPv4ToUint32(v.OuterAddr),
				Port: v.OuterPort,
			}
			switch v.Protocol {
			case "ICMP":
				err = objs.Inner2outerV4Icmp.Delete(tInner)
				if err != nil {
					log.Printf("failed to delete %v from inner2outer_v4_icmp", tInner)
				}
				err = objs.Outer2innerV4Icmp.Delete(tOuter)
				if err != nil {
					log.Printf("failed to delete %v from outer2inner_v4_icmp", tOuter)
				}
			case "UDP":
				err = objs.Inner2outerV4Udp.Delete(tInner)
				if err != nil {
					log.Printf("failed to delete %v from inner2outer_v4_udp", tInner)
				}
				err = objs.Outer2innerV4Udp.Delete(tOuter)
				if err != nil {
					log.Printf("failed to delete %v from outer2inner_v4_udp", tOuter)
				}
				err = objs.ReservedPortV4Udp.Put(nil, tOuter.Port)
				if err != nil {
					log.Printf("failed to put %q to reserved_port_v4_udp", tOuter.Port)
				}
			case "TCP":
				err = objs.Inner2outerV4Tcp.Delete(tInner)
				if err != nil {
					log.Printf("failed to delete %v from inner2outer_v4_tcp", tInner)
				}
				err = objs.Outer2innerV4Tcp.Delete(tOuter)
				if err != nil {
					log.Printf("failed to delete %v from outer2inner_v4_tcp", tOuter)
				}
				err = objs.StateV4Tcp.Delete(tInner)
				if err != nil {
					log.Printf("failed to delete %v from state_v4_tcp", tOuter)
				}
				err = objs.ReservedPortV4Tcp.Put(nil, tOuter.Port)
				if err != nil {
					log.Printf("failed to put %q to reserved_port_v4_tcp", tOuter.Port)
				}
			}
		}
	}
}

func readNatTable(m *ebpf.Map) (map[V4TupleC]V4CTC, error) {
	var key []byte
	var val []byte
	res := map[V4TupleC]V4CTC{}
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		reader := bytes.NewReader(key)
		var k V4TupleC
		binary.Read(reader, binary.LittleEndian, &k)

		reader = bytes.NewReader(val)
		var v V4CTC
		binary.Read(reader, binary.LittleEndian, &v)

		res[k] = v
	}

	return res, iter.Err()
}
