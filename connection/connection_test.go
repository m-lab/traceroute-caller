package connection

import (
	"errors"
	"log"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/inetdiag"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func TestUUID(t *testing.T) {
	conn := Connection{Cookie: "1be3"}
	tmp, err := conn.UUID()
	s := strings.Split(tmp, "_")
	if err != nil || s[len(s)-1] != "0000000000001BE3" {
		t.Error("Make uuid from cookie incorrect")
	}
}

func TestSrcDestSwap(t *testing.T) {
	oldFunc := netInterfaceAddrs
	defer func() { netInterfaceAddrs = oldFunc }()

	netInterfaceAddrs = func() ([]net.Addr, error) {
		_, nw, err := net.ParseCIDR("127.0.0.1/8")
		rtx.Must(err, "could not parse test nw")
		ip1, err := net.ResolveIPAddr("ip6", "::1")
		rtx.Must(err, "failed to resolve ::1")
		ip2, err := net.ResolveIPAddr("ip4", "1.2.3.4")
		rtx.Must(err, "failed to resolve 1.2.3.4")
		return []net.Addr{
			nw,
			ip1,
			ip2,
		}, nil
	}

	c, err := NewLocalIPs()
	rtx.Must(err, "failed to use fake netInterfaceAddrs")

	tests := []struct {
		name    string
		sockid  inetdiag.SockID
		want    Connection
		wantErr bool
	}{
		{
			name: "From local to remote",
			sockid: inetdiag.SockID{
				SrcIP:  "1.2.3.4",
				SPort:  5,
				DstIP:  "7.8.9.10",
				DPort:  11,
				Cookie: 0xc,
			},
			want: Connection{
				LocalIP:    "1.2.3.4",
				LocalPort:  5,
				RemoteIP:   "7.8.9.10",
				RemotePort: 11,
				Cookie:     "c",
			},
		},
		{
			name: "From remote to local",
			sockid: inetdiag.SockID{
				DstIP:  "1.2.3.4",
				DPort:  5,
				SrcIP:  "7.8.9.10",
				SPort:  11,
				Cookie: 0xc,
			},
			want: Connection{
				LocalIP:    "1.2.3.4",
				LocalPort:  5,
				RemoteIP:   "7.8.9.10",
				RemotePort: 11,
				Cookie:     "c",
			},
		},
		{
			name: "Nonlocal connection",
			sockid: inetdiag.SockID{
				DstIP:  "13.14.15.16",
				DPort:  17,
				SrcIP:  "7.8.9.10",
				SPort:  11,
				Cookie: 0xc,
			},
			wantErr: true,
		},
		{
			name: "All local",
			sockid: inetdiag.SockID{
				DstIP:  "1.2.3.4",
				DPort:  17,
				SrcIP:  "1.2.3.4",
				SPort:  11,
				Cookie: 0xc,
			},
			wantErr: true,
		},
		{
			name: "Bad IPs",
			sockid: inetdiag.SockID{
				DstIP:  "1.3.4",
				DPort:  17,
				SrcIP:  "2.3.4",
				SPort:  11,
				Cookie: 0xc,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.FromSockID(tt.sockid)
			if (err != nil) != tt.wantErr {
				t.Errorf("creator.FromSockID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("creator.FromSockID() = %v, want %v", got, tt.want)
			}
		})
	}

	c = NewFakeLocalIPs([]*net.IP{}) // Just call it to make sure it doesn't crash.
}

type fakeIP struct{}

func (fakeIP) String() string  { return "" }
func (fakeIP) Network() string { return "" }

func TestNewLocalIPs(t *testing.T) {
	oldFunc := netInterfaceAddrs
	defer func() { netInterfaceAddrs = oldFunc }()

	netInterfaceAddrs = func() ([]net.Addr, error) {
		return nil, errors.New("error for testing")
	}

	_, err := NewLocalIPs()
	if err == nil {
		t.Error("Should have had an error but was nil")
	}

	netInterfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{fakeIP{}}, nil
	}

	_, err = NewLocalIPs()
	if err == nil {
		t.Error("Should have had an error but was nil")
	}
}
