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
	// cookie is a hexdecimal string
	result, err := strconv.ParseUint(c.Cookie, 16, 64)
	return uuid.FromCookie(result), err
}

type creator struct {
	localIPs []*net.IP
}

// FromSockID converts a SockID into a Connection.
func (c *creator) FromSockID(sockid inetdiag.SockID) (Connection, error) {
	srcIP := net.ParseIP(sockid.SrcIP)
	dstIP := net.ParseIP(sockid.DstIP)
	for _, local := range c.localIPs {
		if local.Equal(srcIP) {
			return Connection{
				RemoteIP:   sockid.DstIP,
				RemotePort: int(sockid.DPort),
				LocalIP:    sockid.SrcIP,
				LocalPort:  int(sockid.SPort),
				Cookie:     strconv.FormatUint(sockid.CookieUint64(), 16),
			}, nil
		}
		if local.Equal(dstIP) {
			return Connection{
				RemoteIP:   sockid.SrcIP,
				RemotePort: int(sockid.SPort),
				LocalIP:    sockid.DstIP,
				LocalPort:  int(sockid.DPort),
				Cookie:     strconv.FormatUint(sockid.CookieUint64(), 16),
			}, nil

		}
	}
	return Connection{}, fmt.Errorf("Could not find a local IP in %+v", sockid)
}

// Creator allows you to create a connection object from a SockID. It properly
// assigns SrcIP and DestIP to RemoteIP and LocalIP.
type Creator interface {
	FromSockID(sockid inetdiag.SockID) (Connection, error)
}

// NewCreator makes an object that can convert src and dst into local and remote
// IPs.
func NewCreator() (Creator, error) {
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
			return c, fmt.Errorf("Unknown type of address %q", addr.String())
		}
		c.localIPs = append(c.localIPs, &ip)
	}

	return c, err
}

// NewFakeCreator makes a fake creator with hardcoded local IPs to enable
// testing in diverse network environments.
func NewFakeCreator(localIPs []*net.IP) Creator {
	return &creator{
		localIPs: localIPs,
	}
}
