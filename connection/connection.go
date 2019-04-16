// Package connection provides a struct to encode a single TCP connection.
package connection

import (
	"strconv"

	"github.com/m-lab/uuid"
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
