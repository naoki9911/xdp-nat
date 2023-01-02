package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp/xdp.c -- -I./xdp/headers

type V4TupleC struct {
	SrcAddr uint32
	DstAddr uint32
	SrcPort uint16
	DstPort uint16
}

type V4Tuple struct {
	SrcAddr net.IP
	DstAddr net.IP
	SrcPort uint16
	DstPort uint16
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
		SrcPort: v.SrcPort,
		DstPort: v.DstPort,
	}
	res.SrcAddr = Uint32ToIPv4(v.SrcAddr)
	res.DstAddr = Uint32ToIPv4(v.DstAddr)

	return res
}

type V4CTC struct {
	InnerAddr uint32
	OuterAddr uint32
	InnerPort uint16
	OuterPort uint16
	PktCount  uint32
}

type V4CT struct {
	InnerAddr net.IP
	OuterAddr net.IP
	InnerPort uint16
	OuterPort uint16
	PktCount  uint32
}

func (v V4CTC) ToGo() V4CT {
	res := V4CT{
		InnerPort: v.InnerPort,
		OuterPort: v.OuterPort,
		PktCount:  v.PktCount,
	}

	res.InnerAddr = Uint32ToIPv4(v.InnerAddr)
	res.OuterAddr = Uint32ToIPv4(v.OuterAddr)

	return res
}

type ConfigC struct {
	InnerIfIndex uint16
	OuterIfIndex uint16
	InnerAddr    uint32
	OuterAddr    uint32
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

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpNatInner2outerFunc,
		Interface: innerIf.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

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
		t, err := readNatTable(objs.Inner2outerV4Tcp)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Println("Inner2outer:")
		for kc, vc := range t {
			k := kc.ToGo()
			v := vc.ToGo()
			log.Printf(" srcAddr=%s:%d dstAddr=%s:%d =>\n", k.SrcAddr, k.SrcPort, k.DstAddr, k.DstPort)
			log.Printf("   innerAddr=%s:%d outerAddr=%s:%d pktCount=%x\n", v.InnerAddr, v.InnerPort, v.OuterAddr, v.OuterPort, v.PktCount)
		}

		t, err = readNatTable(objs.Outer2innerV4Tcp)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Println("Outer2inner:")
		for kc, vc := range t {
			k := kc.ToGo()
			v := vc.ToGo()
			log.Printf(" srcAddr=%s:%d dstAddr=%s:%d =>\n", k.SrcAddr, k.SrcPort, k.DstAddr, k.DstPort)
			log.Printf("   innerAddr=%s:%d outerAddr=%s:%d pktCount=%x\n", v.InnerAddr, v.InnerPort, v.OuterAddr, v.OuterPort, v.PktCount)
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
