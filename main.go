package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TODO: BPF map pinning, share between different programs
// TODO CORE

//go:embed lb_bpfel.o
var lbProgData []byte

type DNATKey struct {
	SAddr uint32
	SPort uint16
	_     uint16
}

type DNATValue struct {
	DAddr uint32
	DPort uint16
	_     uint16
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go lb ebpf/lb.c -- -Iebpf/lib
func main() {
	var sPort uint16
	var dPort uint16

	ifaceName := flag.String("iface", "lo", "interface to bind ebpf program to")
	originalPort := flag.Uint("sport", 10080, "original port before forwarding")
	forwardPort := flag.Uint("dport", 8080, "forward port")
	forwardIP := flag.String("daddr", "192.168.31.10", "forward ip")
	flag.Parse()

	if *ifaceName == "" {
		log.Fatalf("iface name must be specified")
	}
	if *originalPort > uint(65535) || *originalPort < uint(1) {
		log.Fatalf("original port must be between 1 and 65535")
	}
	if *forwardPort > uint(65535) || *forwardPort < uint(1) {
		log.Fatalf("forward port must be between 1 and 65535")
	}
	sPort = uint16(*originalPort)
	dPort = uint16(*forwardPort)
	dIPV4 := net.ParseIP(*forwardIP)
	if dIPV4 == nil {
		log.Fatalf("invalid dip: %s", *forwardIP)
	}

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("cannot find interface %q: %v", *ifaceName, err)
	}

	closeFunc, err := loadEbpf(iface, sPort, dPort, dIPV4)
	if err != nil {
		log.Fatalf("cannot load ebpf program: %v", err)
	}
	defer closeFunc()

	log.Printf("XDP program successfully loaded and attached to %q", *ifaceName)
	log.Printf("Press CTRL+C to stop, will not del tc filter")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig

	// TODO is map cleaned before exit?
}

func loadEbpf(iface *net.Interface, sPort, dPort uint16, dIPV4 net.IP) (func(), error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("cannot get interface addresses: %v", err)
	}
	if len(addrs) > 1 {
		log.Printf("interface %q has more than one address, using the first one", iface.Name)
	}
	sIPV4, _, err := net.ParseCIDR(addrs[0].String())
	if err != nil {
		return nil, fmt.Errorf("cannot parse interface address: %v", err)
	}
	log.Printf("%s:%d -> %s:%d", sIPV4.String(), sPort, dIPV4.String(), dPort)

	objs := &lbObjects{}
	bpfSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(lbProgData))
	if err != nil {
		return nil, fmt.Errorf("cannot load collection spec: %v", err)
	}

	// From Leon: need to specify type for tc ebpf program
	for _, p := range bpfSpec.Programs {
		p.Type = ebpf.SchedCLS
	}

	if err := bpfSpec.LoadAndAssign(objs, nil); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Printf("Verifier error: %+v\n", verr)
		}
		return nil, fmt.Errorf("cannot load and assign bpfSpec: %v", err)
	}

	err = objs.lbMaps.DnatMap.Put(DNATKey{SPort: sPort, SAddr: ip2Uint32(sIPV4)}, DNATValue{DPort: dPort, DAddr: ip2Uint32(dIPV4)})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("cannot put DNAT map: %v", err)
	}

	// Create tc filter and attach ebpf prog to egress

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	err = netlink.QdiscReplace(qdisc)
	if err != nil {
		objs.Close()
		// l.Close()
		return nil, fmt.Errorf("failed to replace qdisc: %v", err)
	}

	egressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  20,
		},
		Fd:           objs.SimpleLbEgress.FD(),
		Name:         "simple-lb-egress",
		DirectAction: true,
	}

	err = netlink.FilterReplace(egressFilter)
	if err != nil {
		objs.Close()
		// l.Close()
		return nil, fmt.Errorf("replace simple-lb-egress ebpf filter failed: %v", err)
	}

	ingressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  20,
		},
		Fd:           objs.SimpleLbIngress.FD(),
		Name:         "simple-lb-ingress",
		DirectAction: true,
	}
	err = netlink.FilterReplace(ingressFilter)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("add simple-lb-ingress ebpf filter failed: %v", err)
	}

	closeFunc := func() {
		objs.Close()
		// l.Close()
	}

	return closeFunc, nil
}

func ip2Uint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}
