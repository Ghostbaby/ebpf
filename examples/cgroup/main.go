package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
	"syscall"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -target amd64,arm64 bpf main.c -- -I../headers_all

func main() {
	// Remove memory limit for eBPF programs
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to remove memlock limit: %v\n", err)
		os.Exit(1)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	spec, err := btf.LoadSpec("/data/gb/external.btf")
	if err != nil {
		log.Fatalf("loading BTF: %v", err)
	}
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: spec,
		},
	}

	if err := loadBpfObjects(&objs, opts); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Set up a perf reader to read events from the eBPF program
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Creating perf reader failed: %v\n", err)
		os.Exit(1)
	}
	defer rd.Close()

	// Set up a channel to receive signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	fmt.Println("Listening for events..")

	// Loop to read events
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Reading from perf reader failed: %v\n", err)
				os.Exit(1)
			}

			// Parse event data
			var e bpfEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
				fmt.Fprintf(os.Stderr, "Parsing event data failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Event Pid: %d, Cgroup ID: %d \n, Cgroup path: %s", e.Pid, e.CgroupId, convertInt8ToBytes(e.CgroupName[:]))

		}
	}()

	// Wait for a signal to exit
	<-sig
	fmt.Println("Exiting..")

}

func convertInt8ToBytes(bs []int8) []byte {
	ba := make([]byte, 0, len(bs))
	for _, b := range bs {
		ba = append(ba, byte(b))
	}
	return ba
}
