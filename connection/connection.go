package connection

import (
	"strconv"

	"github.com/m-lab/go/uuid"
)

type Connection struct {
	Remote_ip   string
	Remote_port int
	Local_ip    string
	Local_port  int
	Cookie      string
}

// UUID returns uuid from cookie parsed from "ss -e" output.
func (c *Connection) UUID() (string, error) {
	// cookie is a hexdecimal string
	result, _ := strconv.ParseUint(c.Cookie, 16, 64)
	return uuid.FromCookie(result)
}
