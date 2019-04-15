package connection

import (
	"log"
	"strconv"

	"github.com/m-lab/uuid"
)

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
	log.Println("GOT:", result, err)
	return uuid.FromCookie(result), err
}
