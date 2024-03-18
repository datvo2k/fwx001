package iptables

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

type Error struct {
	exec.ExitError
	cmd        exec.Cmd
	msg        string
	exitStatus *int
}

func (e *Error) ExitStatus() int {
	if e.exitStatus != nil {
		return *e.exitStatus
	}
	return e.Sys().(syscall.WaitStatus).ExitStatus()
}

func (e *Error) Error() string {
	return fmt.Sprintf("running %v: exit status %v: %v", e.cmd.Args, e.ExitStatus(), e.msg)
}

var isNotExistPatterns = []string{
	"Bad rule (does a matching rule exist in that chain?).\n",
	"No chain/target/match by that name.\n",
	"No such file or directory",
	"does not exist",
}

// IsNotExist returns true if the error is due to the chain or rule not existing
func (e *Error) IsNotExist() bool {
	for _, str := range isNotExistPatterns {
		if strings.Contains(e.msg, str) {
			return true
		}
	}
	return false
}

// Protocol to differentiate between IPv4 and IPv6
type Protocol byte

const (
	ProtocolIPv4 Protocol = iota
	ProtocolIPv6
)

type IPTables struct {
	path              string
	proto             Protocol
	hasCheck          bool
	hasWait           bool
	waitSupportSecond bool
	hasRandomFully    bool
	v1                int
	v2                int
	v3                int
	mode              string // the underlying iptables operating mode, e.g. nf_tables
	timeout           int    // time to wait for the iptables lock, default waits forever
}

// Stat represents a structured statistic entry.
type Stat struct {
	Packets     uint64     `json:"pkts"`
	Bytes       uint64     `json:"bytes"`
	Target      string     `json:"target"`
	Protocol    string     `json:"prot"`
	Opt         string     `json:"opt"`
	Input       string     `json:"in"`
	Output      string     `json:"out"`
	Source      *net.IPNet `json:"source"`
	Destination *net.IPNet `json:"destination"`
	Options     string     `json:"options"`
}

type option func(*IPTables)

func IPFamily(proto Protocol) option {
	return func(ipt *IPTables) {
		ipt.proto = proto
	}
}

func Timeout(timeout int) option {
	return func(ipt *IPTables) {
		ipt.timeout = timeout
	}
}

func Path(path string) option {
	return func(ipt *IPTables) {
		ipt.path = path
	}
}

// New creates a new IPTables configured with the options passed as parameters.
// Supported parameters are:
//
//	IPFamily(Protocol)
//	Timeout(int)
//	Path(string)
//
// For backwards compatibility, by default New uses IPv4 and timeout 0.
// i.e. you can create an IPv6 IPTables using a timeout of 5 seconds passing
// the IPFamily and Timeout options as follow:
//
//	ip6t := New(IPFamily(ProtocolIPv6), Timeout(5))
func new(opts ...option) (*IPTables, error) {
	ipt := &IPTables{
		proto:   ProtocolIPv4,
		timeout: 0,
		path:    "",
	}

	for _, opt := range opts {
		opt(ipt)
	}
}
