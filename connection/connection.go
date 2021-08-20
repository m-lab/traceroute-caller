// Package connection provides a struct to encode a single TCP connection.
package connection

import (
	"fmt"
	"net"
	"strconv"

	"github.com/m-lab/tcp-info/inetdiag"

	"github.com/m-lab/uuid"
)

var (
	// Inject this function to allow whitebox testing of error handling.
	netInterfaceAddrs = net.InterfaceAddrs
)

// Connection models a single connection. This type is checked for equality
// elsewhere in traceroute-caller, so be very careful adding more fields as you
// might accidentally change program semantics elsewhere.
type Connection struct {
	RemoteIP   string
	RemotePort int
	LocalIP    string
	LocalPort  int
	Cookie     string
}

// UUID returns uuid from cookie parsed from "ss -e" output.
func (c *Connection) UUID() (string, error) {
	// cookie is a hexadecimal string
	result, err := strconv.ParseUint(c.Cookie, 16, 64)
	return uuid.FromCookie(result), err
}

type creator struct {
	localIPs []*net.IP
}

// FromSockID converts a SockID into a Connection. It will only perform the
// conversion if the SockID has two parseable IPs in it, and one of the IPs is
// remote and the other belongs to a local interface.
func (c *creator) FromSockID(sockid inetdiag.SockID) (Connection, error) {
	srcIP := net.ParseIP(sockid.SrcIP)
	dstIP := net.ParseIP(sockid.DstIP)
	if srcIP == nil || dstIP == nil {
		return Connection{}, fmt.Errorf("could not convert %q and %q to IPs", sockid.SrcIP, sockid.DstIP)
	}
	srcLocal := false
	dstLocal := false
	for _, local := range c.localIPs {
		srcLocal = srcLocal || local.Equal(srcIP)
		dstLocal = dstLocal || local.Equal(dstIP)
	}
	if srcLocal && !dstLocal {
		return Connection{
			RemoteIP:   sockid.DstIP,
			RemotePort: int(sockid.DPort),
			LocalIP:    sockid.SrcIP,
			LocalPort:  int(sockid.SPort),
			Cookie:     strconv.FormatUint(sockid.CookieUint64(), 16),
		}, nil
	} else if !srcLocal && dstLocal {
		return Connection{
			RemoteIP:   sockid.SrcIP,
			RemotePort: int(sockid.SPort),
			LocalIP:    sockid.DstIP,
			LocalPort:  int(sockid.DPort),
			Cookie:     strconv.FormatUint(sockid.CookieUint64(), 16),
		}, nil
	}
	return Connection{}, fmt.Errorf("could not find a local<->remote IP pair in %+v", sockid)
}

// Creator allows you to create a connection object from a SockID. It properly
// assigns SrcIP and DestIP to RemoteIP and LocalIP.
type Creator interface {
	FromSockID(sockid inetdiag.SockID) (Connection, error)
}

// NewLocalRemoteIPs makes an object that can convert src and dst into local
// and remote IPs.
func NewLocalRemoteIPs() (Creator, error) {
	c := &creator{
		localIPs: make([]*net.IP, 0),
	}

	addrs, err := netInterfaceAddrs()
	if err != nil {
		return c, err
	}
	for _, addr := range addrs {
		var ip net.IP
		switch a := addr.(type) {
		case *net.IPNet:
			ip = a.IP
		case *net.IPAddr:
			ip = a.IP
		default:
			return c, fmt.Errorf("unknown type of address %q", addr.String())
		}
		if ip != nil {
			c.localIPs = append(c.localIPs, &ip)
		}
	}

	return c, err
}

// NewFakeLocalIPs makes a fake creator with hardcoded local IPs to
// enable testing in diverse network environments.
func NewFakeLocalIPs(localIPs []*net.IP) Creator {
	return &creator{
		localIPs: localIPs,
	}
}
