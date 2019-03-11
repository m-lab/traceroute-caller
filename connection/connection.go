package connection

import (
	"strconv"

	"github.com/m-lab/go/uuid"
)

type Connection struct {
	remote_ip   string
	remote_port int
	local_ip    string
	local_port  int
	cookie      string
}

// MakeUUID returns uuid from cookie parsed from "ss -e" output.
func MakeUUID(cookie string) (string, error) {
	// cookie is a hexdecimal string
	result, _ := strconv.ParseUint(cookie, 16, 64)
	return uuid.FromCookie(result)
}
