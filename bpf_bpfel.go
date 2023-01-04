// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	XdpNatInner2outerFunc *ebpf.ProgramSpec `ebpf:"xdp_nat_inner2outer_func"`
	XdpNatOuter2innerFunc *ebpf.ProgramSpec `ebpf:"xdp_nat_outer2inner_func"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	Configs           *ebpf.MapSpec `ebpf:"configs"`
	Inner2outerV4Icmp *ebpf.MapSpec `ebpf:"inner2outer_v4_icmp"`
	Inner2outerV4Tcp  *ebpf.MapSpec `ebpf:"inner2outer_v4_tcp"`
	Inner2outerV4Udp  *ebpf.MapSpec `ebpf:"inner2outer_v4_udp"`
	Outer2innerV4Icmp *ebpf.MapSpec `ebpf:"outer2inner_v4_icmp"`
	Outer2innerV4Tcp  *ebpf.MapSpec `ebpf:"outer2inner_v4_tcp"`
	Outer2innerV4Udp  *ebpf.MapSpec `ebpf:"outer2inner_v4_udp"`
	ReservedPortV4Tcp *ebpf.MapSpec `ebpf:"reserved_port_v4_tcp"`
	ReservedPortV4Udp *ebpf.MapSpec `ebpf:"reserved_port_v4_udp"`
	StateV4Tcp        *ebpf.MapSpec `ebpf:"state_v4_tcp"`
	XdpStatsMap       *ebpf.MapSpec `ebpf:"xdp_stats_map"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	Configs           *ebpf.Map `ebpf:"configs"`
	Inner2outerV4Icmp *ebpf.Map `ebpf:"inner2outer_v4_icmp"`
	Inner2outerV4Tcp  *ebpf.Map `ebpf:"inner2outer_v4_tcp"`
	Inner2outerV4Udp  *ebpf.Map `ebpf:"inner2outer_v4_udp"`
	Outer2innerV4Icmp *ebpf.Map `ebpf:"outer2inner_v4_icmp"`
	Outer2innerV4Tcp  *ebpf.Map `ebpf:"outer2inner_v4_tcp"`
	Outer2innerV4Udp  *ebpf.Map `ebpf:"outer2inner_v4_udp"`
	ReservedPortV4Tcp *ebpf.Map `ebpf:"reserved_port_v4_tcp"`
	ReservedPortV4Udp *ebpf.Map `ebpf:"reserved_port_v4_udp"`
	StateV4Tcp        *ebpf.Map `ebpf:"state_v4_tcp"`
	XdpStatsMap       *ebpf.Map `ebpf:"xdp_stats_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.Configs,
		m.Inner2outerV4Icmp,
		m.Inner2outerV4Tcp,
		m.Inner2outerV4Udp,
		m.Outer2innerV4Icmp,
		m.Outer2innerV4Tcp,
		m.Outer2innerV4Udp,
		m.ReservedPortV4Tcp,
		m.ReservedPortV4Udp,
		m.StateV4Tcp,
		m.XdpStatsMap,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	XdpNatInner2outerFunc *ebpf.Program `ebpf:"xdp_nat_inner2outer_func"`
	XdpNatOuter2innerFunc *ebpf.Program `ebpf:"xdp_nat_outer2inner_func"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.XdpNatInner2outerFunc,
		p.XdpNatOuter2innerFunc,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed bpf_bpfel.o
var _BpfBytes []byte
