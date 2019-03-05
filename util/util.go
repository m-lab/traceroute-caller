package util

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The new test output filename is joint of hostname, server boot time, and socker TCO cookie.
// like: pboothe2.nyc.corp.google.com_1548788619_00000000000084FF
var IGNORE_IPV4_NETS = []string{"127.", "128.112.139.", "::ffff:127.0.0.1"}

// MakeFilename as logtime_
// 2019-02-04T18:01:10Z-76.14.89.46.json
func MakeFilename(ip string) string {
	t := time.Now()
	return fmt.Sprintf("%s-%s.json", t.Format(time.RFC3339), ip)

}

func GetHostname() string {
	hostname, _ := exec.Command("hostname").Output()
	out := string(hostname)
	return strings.TrimSuffix(out, "\n")
}

func MakeUUID(cookie string) (string, error) {
	stat, err := os.Stat("/proc")
	if err != nil {
		return "", err
	}

	// cookie is a hexdecimal string
	result, _ := strconv.ParseUint(cookie, 16, 64)
	return fmt.Sprintf("%s_%d_%016X", GetHostname(), stat.ModTime().Unix(), uint64(result)), nil
}

func ParseIPAndPort(input string) (string, int, error) {
	seperator := strings.LastIndex(input, ":")
	if seperator == -1 {
		return "", 0, errors.New("cannot parse IP and port correctly")
	}
	IPStr := input[0:seperator]
	if IPStr[0] == '[' {
		IPStr = IPStr[1 : len(IPStr)-1]
	}
	for _, prefix := range IGNORE_IPV4_NETS {
		if strings.HasPrefix(IPStr, prefix) {
			return "", 0, errors.New("ignore this IP address")
		}
	}
	outputIP := net.ParseIP(IPStr)
	if outputIP == nil {
		return "", 0, errors.New("invalid IP address")
	}

	port, err := strconv.Atoi(input[seperator+1:])
	if err != nil {
		return "", 0, errors.New("invalid IP port")
	}
	return IPStr, port, nil
}

func ParseCookie(input string) (string, error) {
	if !strings.HasPrefix(input, "sk:") {
		return "", errors.New("no cookie")
	}
	return input[3:], nil
}

// GetHostnamePrefix returns first two seg, like "mlab1.ath03" from hostname.
func GetHostnamePrefix() string {
	hostname := GetHostname()
	segs := strings.Split(hostname, ".")
	if len(segs) < 2 {
		return hostname
	}
	return segs[0] + "." + segs[1]
}

// CreateTimePath return a string with date in format yyyy/mm/dd/
func CreateTimePath(prefix string) string {
	currentTime := time.Now().Format("2006-01-02")
	date := strings.Split(currentTime, "-")
	if len(date) != 3 {
		return ""
	}
	if _, err := os.Stat(prefix + date[0]); os.IsNotExist(err) {
		os.Mkdir(prefix+date[0], 0700)
	}
	if _, err := os.Stat(prefix + date[0] + "/" + date[1]); os.IsNotExist(err) {
		os.Mkdir(prefix+date[0]+"/"+date[1], 0700)
	}
	if _, err := os.Stat(prefix + date[0] + "/" + date[1] + "/" + date[2]); os.IsNotExist(err) {
		os.Mkdir(prefix+date[0]+"/"+date[1]+"/"+date[2], 0700)
	}
	hostnamePrefix := GetHostnamePrefix()
	if _, err := os.Stat(prefix + date[0] + "/" + date[1] + "/" + date[2] + "/" + hostnamePrefix); os.IsNotExist(err) {
		os.Mkdir(prefix+date[0]+"/"+date[1]+"/"+date[2]+"/"+hostnamePrefix, 0700)
	}
	return prefix + date[0] + "/" + date[1] + "/" + date[2] + "/" + hostnamePrefix + "/"
}

// ///////////////////////////////////////////////////////////////////////

// Do not traceroute to an IP more than once in this many seconds
var IP_CACHE_TIME_SECONDS = 120

var MAX_CACHE_ENTRY = 1000

type RecentIPCache struct {
	cache map[string]int64
	mu    sync.RWMutex
}

func (m *RecentIPCache) New() {
	m.mu.Lock()
	m.cache = make(map[string]int64)
	m.mu.Unlock()
	go func() {
		for now := range time.Tick(time.Second) {
			//m.mu.RLock()
			//defer m.mu.RUnlock()
			//fmt.Printf("func Tick: Now is %d, length of cache: %d \n", now.Unix(), len(m.cache))

			for k, v := range m.cache {
				//fmt.Printf("entry %s is %d\n", k, v)
				if now.Unix()-v > int64(IP_CACHE_TIME_SECONDS) {
					fmt.Println("try to delete " + k)
					m.mu.Lock()
					delete(m.cache, k)
					fmt.Println("delete done")
					m.mu.Unlock()
				}
			}
		}

	}()
	return
}

func (m *RecentIPCache) Flush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache = make(map[string]int64)
}

func (m *RecentIPCache) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cache)
}

func (m *RecentIPCache) Add(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Printf("func Add: Now is %d\n", time.Now().Unix())
	_, ok := m.cache[ip]
	if !ok || m.Len() == 0 {
		if m.cache == nil {
			m.cache = make(map[string]int64)
		}
		m.cache[ip] = time.Now().Unix()
		fmt.Printf("just add %s %d\n", ip, m.cache[ip])
	}
}

func (m *RecentIPCache) Has(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	//fmt.Printf("func Has: Now is %d, length of cache: %d \n", time.Now().Unix(), m.Len())
	if m.Len() == 0 {
		return false
	}
	_, ok := m.cache[ip]
	return ok
}
