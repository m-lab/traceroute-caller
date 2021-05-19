package parser_test

import (
	"fmt"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/m-lab/traceroute-caller/parser"
	"github.com/m-lab/traceroute-caller/schema"
)

func TestParseJsonSimple(t *testing.T) {
	testStr := `{"UUID": "ndt-plh7v_1566050090_000000000004D64D"}
{"type":"cycle-start", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "start_time":1566691298}
{"type":"tracelb", "version":"0.1", "userid":0, "method":"icmp-echo", "src":"::ffff:180.87.97.101", "dst":"::ffff:1.47.236.62", "start":{"sec":1566691298, "usec":476221, "ftime":"2019-08-25 00:01:38"}, "probe_size":60, "firsthop":1, "attempts":3, "confidence":95, "tos":0, "gaplimit":3, "wait_timeout":5, "wait_probe":250, "probec":0, "probec_max":3000, "nodec":0, "linkc":0}
{"type":"cycle-stop", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "stop_time":1566691298}
`
	output, err := parser.ParseJSON("20190825T000138Z_ndt-plh7v_1566050090_000000000004D64D.jsonl", []byte(testStr))
	if err != nil {
		t.Fatalf("Err during json parsing %v", err)
	}
	if output.UUID != "ndt-plh7v_1566050090_000000000004D64D" {
		t.Fatalf("Wrong results for UUID parsing!")
	}
	if output.ServerIP != "::ffff:180.87.97.101" || output.ClientIP != "::ffff:1.47.236.62" {
		t.Fatalf("Wrong results for source/destination IP parsing!")
	}
	if output.ProbeSize != 60 || output.ProbeC != 0 {
		t.Fatalf("Wrong results for probe size or probec parsing!")
	}
}

func TestParseJsonFailure(t *testing.T) {
	testStr := `{"TracerouteCallerVersion":"bc092be"}
		{"type":"cycle-start", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "start_time":1566691298}
		{"type":"tracelb", "version":"0.1", "userid":0, "method":"icmp-echo", "src":"::ffff:180.87.97.101", "dst":"::ffff:1.47.236.62", "start":{"sec":1566691298, "usec":476221, "ftime":"2019-08-25 00:01:38"}, "probe_size":60, "firsthop":1, "attempts":3, "confidence":95, "tos":0, "gaplimit":3, "wait_timeout":5, "wait_probe":250, "probec":0, "probec_max":3000, "nodec":0, "linkc":0}
		{"type":"cycle-stop", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "stop_time":1566691298}
		`
	_, err := parser.ParseJSON("xxxx.jsonl", []byte(testStr))
	if err.Error() != "no date in filename" {
		t.Fatalf("fail to detect wrong filename")
	}
	_, err = parser.ParseJSON("20190825T000138Z_ndt-plh7v_1566050090_000000000004D64D.jsonl", []byte(testStr))
	if err == nil || err.Error() != "empty UUID" {
		t.Fatalf("fail to detect missing UUID")
	}
	testStr = `{"TracerouteCallerVersion":"bc092be"}
			   {"type":"cycle-start", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "start_time":1566691298}
			   {"type":"tracelb", "version":"0.1", "userid":0, "method":"icmp-echo", "src":"::ffff:180.87.97.101", "dst":"::ffff:1.47.236.62", "start":{"sec":1566691298, "usec":476221, "ftime":"2019-08-25 00:01:38"}, "probe_size":60, "firsthop":1, "attempts":3, "confidence":95, "tos":0, "gaplimit":3, "wait_timeout":5, "wait_probe":250, "probec":0, "probec_max":3000, "nodec":0, "linkc":0}
			   {"type":"cycle-stop", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "stop_time":1566691298}
			   {"type":"cycle-extra"}
			   `
	_, err = parser.ParseJSON("20190825T000138Z_ndt-plh7v_1566050090_000000000004D64D.jsonl", []byte(testStr))
	if err.Error() != "invalid test" {
		t.Fatalf("fail to detect corrupted test")
	}
	testStr = `{"Unknown:"bc092be"}
{"type":"cycle-start", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "start_time":1566691298}
{"type":"tracelb", "version":"0.1", "userid":0, "method":"icmp-echo", "src":"::ffff:180.87.97.101", "dst":"::ffff:1.47.236.62", "start":{"sec":1566691298, "usec":476221, "ftime":"2019-08-25 00:01:38"}, "probe_size":60, "firsthop":1, "attempts":3, "confidence":95, "tos":0, "gaplimit":3, "wait_timeout":5, "wait_probe":250, "probec":0, "probec_max":3000, "nodec":0, "linkc":0}
{"type":"cycle-stop", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "stop_time":1566691298}
`
	_, err = parser.ParseJSON("20190825T000138Z_ndt-plh7v_1566050090_000000000004D64D.jsonl", []byte(testStr))
	if err.Error() != "invalid meta" {
		t.Fatalf("fail to detect corrupted meta")
	}
	testStr = `{"UUID":"ndt-v595x_1572645241_0000000000000626"}
{"type":"cycle-start, "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "start_time":1566691298}
{"type":"tracelb", "version":"0.1", "userid":0, "method":"icmp-echo", "src":"::ffff:180.87.97.101", "dst":"::ffff:1.47.236.62", "start":{"sec":1566691298, "usec":476221, "ftime":"2019-08-25 00:01:38"}, "probe_size":60, "firsthop":1, "attempts":3, "confidence":95, "tos":0, "gaplimit":3, "wait_timeout":5, "wait_probe":250, "probec":0, "probec_max":3000, "nodec":0, "linkc":0}
{"type":"cycle-stop", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "stop_time":1566691298}
`
	_, err = parser.ParseJSON("20190825T000138Z_ndt-plh7v_1566050090_000000000004D64D.jsonl", []byte(testStr))
	if err.Error() != "invalid cycle-start" {
		t.Fatalf("fail to detect corrupted cycle-start")
	}
	testStr = `{"UUID":"ndt-v595x_1572645241_0000000000000626"}
{"type":"cycle-start", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "start_time":1566691298}
{"type":"tracelb, "version":"0.1", "userid":0, "method":"icmp-echo", "src":"::ffff:180.87.97.101", "dst":"::ffff:1.47.236.62", "start":{"sec":1566691298, "usec":476221, "ftime":"2019-08-25 00:01:38"}, "probe_size":60, "firsthop":1, "attempts":3, "confidence":95, "tos":0, "gaplimit":3, "wait_timeout":5, "wait_probe":250, "probec":0, "probec_max":3000, "nodec":0, "linkc":0}
{"type":"cycle-stop", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "stop_time":1566691298}
`
	_, err = parser.ParseJSON("20190825T000138Z_ndt-plh7v_1566050090_000000000004D64D.jsonl", []byte(testStr))
	if err.Error() != "invalid tracelb" {
		t.Fatalf("fail to detect corrupted tracelb")
	}
	testStr = `{"UUID":"ndt-v595x_1572645241_0000000000000626"}
{"type":"cycle-start", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "start_time":1566691298}
{"type":"tracelb", "version":"0.1", "userid":0, "method":"icmp-echo", "src":"::ffff:180.87.97.101", "dst":"::ffff:1.47.236.62", "start":{"sec":1566691298, "usec":476221, "ftime":"2019-08-25 00:01:38"}, "probe_size":60, "firsthop":1, "attempts":3, "confidence":95, "tos":0, "gaplimit":3, "wait_timeout":5, "wait_probe":250, "probec":0, "probec_max":3000, "nodec":0, "linkc":0}
{"type":"cycle-stop, "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "stop_time":1566691298}
`
	_, err = parser.ParseJSON("20190825T000138Z_ndt-plh7v_1566050090_000000000004D64D.jsonl", []byte(testStr))
	if err.Error() != "invalid cycle-stop" {
		t.Fatalf("fail to detect corrupted cycle-stop")
	}
}

func TestParseJsonNoLinks(t *testing.T) {
	// Last object on the "type":"tracelb" line has "linkc":1 but no "links" set.
	testStr := `{"UUID": "ndt-plh7v_1566050090_000000000004D60F"}
	{"type":"cycle-start", "list_name":"/tmp/scamperctrl:51803", "id":1, "hostname":"ndt-plh7v", "start_time":1566691268}
	{"type":"tracelb", "version":"0.1", "userid":0, "method":"icmp-echo", "src":"2001:550:1b01:1:e41d:2d00:151:f6c0", "dst":"2600:1009:b013:1a59:c369:b528:98fd:ab43", "start":{"sec":1567900908, "usec":729543, "ftime":"2019-09-08 00:01:48"}, "probe_size":60, "firsthop":1, "attempts":3, "confidence":95, "tos":0, "gaplimit":3, "wait_timeout":5, "wait_probe":250, "probec":85, "probec_max":3000, "nodec":6, "linkc":6, "nodes":[{"addr":"2001:550:1b01:1::1", "q_ttl":1, "linkc":1, "links":[[{"addr":"2001:550:3::1ca", "probes":[{"tx":{"sec":1567900908, "usec":979595}, "replyc":1, "ttl":2, "attempt":0, "flowid":1, "replies":[{"rx":{"sec":1567900909, "usec":16398}, "ttl":63, "rtt":36.803, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900909, "usec":229642}, "replyc":1, "ttl":2, "attempt":0, "flowid":2, "replies":[{"rx":{"sec":1567900909, "usec":229974}, "ttl":63, "rtt":0.332, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900909, "usec":480242}, "replyc":1, "ttl":2, "attempt":0, "flowid":3, "replies":[{"rx":{"sec":1567900909, "usec":480571}, "ttl":63, "rtt":0.329, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900909, "usec":730987}, "replyc":1, "ttl":2, "attempt":0, "flowid":4, "replies":[{"rx":{"sec":1567900909, "usec":731554}, "ttl":63, "rtt":0.567, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900909, "usec":982029}, "replyc":1, "ttl":2, "attempt":0, "flowid":5, "replies":[{"rx":{"sec":1567900909, "usec":982358}, "ttl":63, "rtt":0.329, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900910, "usec":232994}, "replyc":1, "ttl":2, "attempt":0, "flowid":6, "replies":[{"rx":{"sec":1567900910, "usec":234231}, "ttl":63, "rtt":1.237, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]}]}]]},{"addr":"2001:550:3::1ca", "q_ttl":1, "linkc":1, "links":[[{"addr":"2600:803::79", "probes":[{"tx":{"sec":1567900910, "usec":483606}, "replyc":1, "ttl":3, "attempt":0, "flowid":1, "replies":[{"rx":{"sec":1567900910, "usec":500939}, "ttl":58, "rtt":17.333, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900910, "usec":734394}, "replyc":1, "ttl":3, "attempt":0, "flowid":2, "replies":[{"rx":{"sec":1567900910, "usec":752612}, "ttl":58, "rtt":18.218, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900910, "usec":985425}, "replyc":1, "ttl":3, "attempt":0, "flowid":3, "replies":[{"rx":{"sec":1567900911, "usec":6498}, "ttl":58, "rtt":21.073, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900911, "usec":235481}, "replyc":1, "ttl":3, "attempt":0, "flowid":4, "replies":[{"rx":{"sec":1567900911, "usec":252800}, "ttl":58, "rtt":17.319, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900911, "usec":486164}, "replyc":1, "ttl":3, "attempt":0, "flowid":5, "replies":[{"rx":{"sec":1567900911, "usec":503522}, "ttl":58, "rtt":17.358, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900911, "usec":737096}, "replyc":1, "ttl":3, "attempt":0, "flowid":6, "replies":[{"rx":{"sec":1567900911, "usec":760439}, "ttl":58, "rtt":23.343, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]}]}]]},{"addr":"2600:803::79", "q_ttl":1, "linkc":1, "links":[[{"addr":"2600:803:150f::4a", "probes":[{"tx":{"sec":1567900911, "usec":987801}, "replyc":1, "ttl":4, "attempt":0, "flowid":1, "replies":[{"rx":{"sec":1567900912, "usec":10282}, "ttl":57, "rtt":22.481, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900912, "usec":238227}, "replyc":1, "ttl":4, "attempt":0, "flowid":2, "replies":[{"rx":{"sec":1567900912, "usec":262270}, "ttl":57, "rtt":24.043, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900912, "usec":539699}, "replyc":1, "ttl":4, "attempt":0, "flowid":3, "replies":[{"rx":{"sec":1567900912, "usec":562078}, "ttl":57, "rtt":22.379, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900912, "usec":789753}, "replyc":1, "ttl":4, "attempt":0, "flowid":4, "replies":[{"rx":{"sec":1567900912, "usec":812145}, "ttl":57, "rtt":22.392, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900913, "usec":42261}, "replyc":1, "ttl":4, "attempt":0, "flowid":5, "replies":[{"rx":{"sec":1567900913, "usec":64678}, "ttl":57, "rtt":22.417, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900913, "usec":292682}, "replyc":1, "ttl":4, "attempt":0, "flowid":6, "replies":[{"rx":{"sec":1567900913, "usec":315254}, "ttl":57, "rtt":22.572, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]}]}]]},{"addr":"2600:803:150f::4a", "q_ttl":1, "linkc":1, "links":[[{"addr":"2001:4888:36:1002:3a2:1:0:1", "probes":[{"tx":{"sec":1567900913, "usec":543335}, "replyc":1, "ttl":5, "attempt":0, "flowid":1, "replies":[{"rx":{"sec":1567900913, "usec":568980}, "ttl":56, "rtt":25.645, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900913, "usec":793793}, "replyc":1, "ttl":5, "attempt":0, "flowid":2, "replies":[{"rx":{"sec":1567900913, "usec":816848}, "ttl":56, "rtt":23.055, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900914, "usec":43821}, "replyc":1, "ttl":5, "attempt":0, "flowid":3, "replies":[{"rx":{"sec":1567900914, "usec":72827}, "ttl":56, "rtt":29.006, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900914, "usec":294820}, "replyc":1, "ttl":5, "attempt":0, "flowid":4, "replies":[{"rx":{"sec":1567900914, "usec":320815}, "ttl":56, "rtt":25.995, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900914, "usec":545802}, "replyc":1, "ttl":5, "attempt":0, "flowid":5, "replies":[{"rx":{"sec":1567900914, "usec":568924}, "ttl":56, "rtt":23.122, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900914, "usec":796839}, "replyc":1, "ttl":5, "attempt":0, "flowid":6, "replies":[{"rx":{"sec":1567900914, "usec":824735}, "ttl":56, "rtt":27.896, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]}]}]]},{"addr":"2001:4888:36:1002:3a2:1:0:1", "q_ttl":1, "linkc":1, "links":[[{"addr":"2001:4888:3f:6092:3a2:26:0:1", "probes":[{"tx":{"sec":1567900915, "usec":46897}, "replyc":1, "ttl":6, "attempt":0, "flowid":1, "replies":[{"rx":{"sec":1567900915, "usec":69996}, "ttl":245, "rtt":23.099, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900915, "usec":297455}, "replyc":1, "ttl":6, "attempt":0, "flowid":2, "replies":[{"rx":{"sec":1567900915, "usec":320524}, "ttl":245, "rtt":23.069, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900915, "usec":547737}, "replyc":1, "ttl":6, "attempt":0, "flowid":3, "replies":[{"rx":{"sec":1567900915, "usec":570899}, "ttl":245, "rtt":23.162, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900915, "usec":798167}, "replyc":1, "ttl":6, "attempt":0, "flowid":4, "replies":[{"rx":{"sec":1567900915, "usec":821218}, "ttl":245, "rtt":23.051, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900916, "usec":55367}, "replyc":1, "ttl":6, "attempt":0, "flowid":5, "replies":[{"rx":{"sec":1567900916, "usec":78485}, "ttl":245, "rtt":23.118, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900916, "usec":306410}, "replyc":1, "ttl":6, "attempt":0, "flowid":6, "replies":[{"rx":{"sec":1567900916, "usec":329419}, "ttl":245, "rtt":23.009, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]}]}]]},{"addr":"2001:4888:3f:6092:3a2:26:0:1", "q_ttl":1, "linkc":1}]}
	{"type":"cycle-stop", "list_name":"/tmp/scamperctrl:51803", "id":1, "hostname":"ndt-plh7v", "stop_time":1566691541}
	`
	_, err := parser.ParseJSON("20190825T000138Z_ndt-plh7v_1566050090_000000000004D64D.jsonl", []byte(testStr))
	if err != nil {
		t.Fatalf("Err during json parsing %v", err)
	}

}
func TestParseJsonComplex(t *testing.T) {
	testStr := `{"UUID":"ndt-plh7v_1566050090_000000000004D60F","TracerouteCallerVersion":"bc092be","CachedResult":true,"CachedUUID":"ndt-w6lxg_1565921414_00000000000038C0"}
	{"type":"cycle-start", "list_name":"/tmp/scamperctrl:51803", "id":1, "hostname":"ndt-plh7v", "start_time":1566691268}
	{"type":"tracelb", "version":"0.1", "userid":0, "method":"icmp-echo", "src":"2001:550:1b01:1:e41d:2d00:151:f6c0", "dst":"2600:1009:b013:1a59:c369:b528:98fd:ab43", "start":{"sec":1567900908, "usec":729543, "ftime":"2019-09-08 00:01:48"}, "probe_size":60, "firsthop":1, "attempts":3, "confidence":95, "tos":0, "gaplimit":3, "wait_timeout":5, "wait_probe":250, "probec":85, "probec_max":3000, "nodec":6, "linkc":6, "nodes":[{"addr":"2001:550:1b01:1::1", "q_ttl":1, "linkc":1, "links":[[{"addr":"2001:550:3::1ca", "probes":[{"tx":{"sec":1567900908, "usec":979595}, "replyc":1, "ttl":2, "attempt":0, "flowid":1, "replies":[{"rx":{"sec":1567900909, "usec":16398}, "ttl":63, "rtt":36.803, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900909, "usec":229642}, "replyc":1, "ttl":2, "attempt":0, "flowid":2, "replies":[{"rx":{"sec":1567900909, "usec":229974}, "ttl":63, "rtt":0.332, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900909, "usec":480242}, "replyc":1, "ttl":2, "attempt":0, "flowid":3, "replies":[{"rx":{"sec":1567900909, "usec":480571}, "ttl":63, "rtt":0.329, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900909, "usec":730987}, "replyc":1, "ttl":2, "attempt":0, "flowid":4, "replies":[{"rx":{"sec":1567900909, "usec":731554}, "ttl":63, "rtt":0.567, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900909, "usec":982029}, "replyc":1, "ttl":2, "attempt":0, "flowid":5, "replies":[{"rx":{"sec":1567900909, "usec":982358}, "ttl":63, "rtt":0.329, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900910, "usec":232994}, "replyc":1, "ttl":2, "attempt":0, "flowid":6, "replies":[{"rx":{"sec":1567900910, "usec":234231}, "ttl":63, "rtt":1.237, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]}]}]]},{"addr":"2001:550:3::1ca", "q_ttl":1, "linkc":1, "links":[[{"addr":"2600:803::79", "probes":[{"tx":{"sec":1567900910, "usec":483606}, "replyc":1, "ttl":3, "attempt":0, "flowid":1, "replies":[{"rx":{"sec":1567900910, "usec":500939}, "ttl":58, "rtt":17.333, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900910, "usec":734394}, "replyc":1, "ttl":3, "attempt":0, "flowid":2, "replies":[{"rx":{"sec":1567900910, "usec":752612}, "ttl":58, "rtt":18.218, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900910, "usec":985425}, "replyc":1, "ttl":3, "attempt":0, "flowid":3, "replies":[{"rx":{"sec":1567900911, "usec":6498}, "ttl":58, "rtt":21.073, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900911, "usec":235481}, "replyc":1, "ttl":3, "attempt":0, "flowid":4, "replies":[{"rx":{"sec":1567900911, "usec":252800}, "ttl":58, "rtt":17.319, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900911, "usec":486164}, "replyc":1, "ttl":3, "attempt":0, "flowid":5, "replies":[{"rx":{"sec":1567900911, "usec":503522}, "ttl":58, "rtt":17.358, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900911, "usec":737096}, "replyc":1, "ttl":3, "attempt":0, "flowid":6, "replies":[{"rx":{"sec":1567900911, "usec":760439}, "ttl":58, "rtt":23.343, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]}]}]]},{"addr":"2600:803::79", "q_ttl":1, "linkc":1, "links":[[{"addr":"2600:803:150f::4a", "probes":[{"tx":{"sec":1567900911, "usec":987801}, "replyc":1, "ttl":4, "attempt":0, "flowid":1, "replies":[{"rx":{"sec":1567900912, "usec":10282}, "ttl":57, "rtt":22.481, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900912, "usec":238227}, "replyc":1, "ttl":4, "attempt":0, "flowid":2, "replies":[{"rx":{"sec":1567900912, "usec":262270}, "ttl":57, "rtt":24.043, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900912, "usec":539699}, "replyc":1, "ttl":4, "attempt":0, "flowid":3, "replies":[{"rx":{"sec":1567900912, "usec":562078}, "ttl":57, "rtt":22.379, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900912, "usec":789753}, "replyc":1, "ttl":4, "attempt":0, "flowid":4, "replies":[{"rx":{"sec":1567900912, "usec":812145}, "ttl":57, "rtt":22.392, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900913, "usec":42261}, "replyc":1, "ttl":4, "attempt":0, "flowid":5, "replies":[{"rx":{"sec":1567900913, "usec":64678}, "ttl":57, "rtt":22.417, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900913, "usec":292682}, "replyc":1, "ttl":4, "attempt":0, "flowid":6, "replies":[{"rx":{"sec":1567900913, "usec":315254}, "ttl":57, "rtt":22.572, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]}]}]]},{"addr":"2600:803:150f::4a", "q_ttl":1, "linkc":1, "links":[[{"addr":"2001:4888:36:1002:3a2:1:0:1", "probes":[{"tx":{"sec":1567900913, "usec":543335}, "replyc":1, "ttl":5, "attempt":0, "flowid":1, "replies":[{"rx":{"sec":1567900913, "usec":568980}, "ttl":56, "rtt":25.645, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900913, "usec":793793}, "replyc":1, "ttl":5, "attempt":0, "flowid":2, "replies":[{"rx":{"sec":1567900913, "usec":816848}, "ttl":56, "rtt":23.055, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900914, "usec":43821}, "replyc":1, "ttl":5, "attempt":0, "flowid":3, "replies":[{"rx":{"sec":1567900914, "usec":72827}, "ttl":56, "rtt":29.006, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900914, "usec":294820}, "replyc":1, "ttl":5, "attempt":0, "flowid":4, "replies":[{"rx":{"sec":1567900914, "usec":320815}, "ttl":56, "rtt":25.995, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900914, "usec":545802}, "replyc":1, "ttl":5, "attempt":0, "flowid":5, "replies":[{"rx":{"sec":1567900914, "usec":568924}, "ttl":56, "rtt":23.122, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900914, "usec":796839}, "replyc":1, "ttl":5, "attempt":0, "flowid":6, "replies":[{"rx":{"sec":1567900914, "usec":824735}, "ttl":56, "rtt":27.896, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]}]}]]},{"addr":"2001:4888:36:1002:3a2:1:0:1", "q_ttl":1, "linkc":1, "links":[[{"addr":"2001:4888:3f:6092:3a2:26:0:1", "probes":[{"tx":{"sec":1567900915, "usec":46897}, "replyc":1, "ttl":6, "attempt":0, "flowid":1, "replies":[{"rx":{"sec":1567900915, "usec":69996}, "ttl":245, "rtt":23.099, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900915, "usec":297455}, "replyc":1, "ttl":6, "attempt":0, "flowid":2, "replies":[{"rx":{"sec":1567900915, "usec":320524}, "ttl":245, "rtt":23.069, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900915, "usec":547737}, "replyc":1, "ttl":6, "attempt":0, "flowid":3, "replies":[{"rx":{"sec":1567900915, "usec":570899}, "ttl":245, "rtt":23.162, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900915, "usec":798167}, "replyc":1, "ttl":6, "attempt":0, "flowid":4, "replies":[{"rx":{"sec":1567900915, "usec":821218}, "ttl":245, "rtt":23.051, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900916, "usec":55367}, "replyc":1, "ttl":6, "attempt":0, "flowid":5, "replies":[{"rx":{"sec":1567900916, "usec":78485}, "ttl":245, "rtt":23.118, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900916, "usec":306410}, "replyc":1, "ttl":6, "attempt":0, "flowid":6, "replies":[{"rx":{"sec":1567900916, "usec":329419}, "ttl":245, "rtt":23.009, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]}]}]]},{"addr":"2001:4888:3f:6092:3a2:26:0:1", "q_ttl":1, "linkc":1, "links":[[{"addr":"*"}],[{"addr":"*"}],]}]}
	{"type":"cycle-stop", "list_name":"/tmp/scamperctrl:51803", "id":1, "hostname":"ndt-plh7v", "stop_time":1566691541}
	`
	output, err := parser.ParseJSON("20190825T000138Z_ndt-plh7v_1566050090_000000000004D64D.jsonl", []byte(testStr))
	expectedHop := schema.ScamperHop{
		Source: schema.HopIP{IP: "2001:550:1b01:1::1"},
		Linkc:  1,
		Links: []schema.HopLink{
			{
				HopDstIP: "2001:550:3::1ca",
				TTL:      2,
				Probes: []schema.HopProbe{
					{Flowid: 1, Rtt: []float64{36.803}},
					{Flowid: 2, Rtt: []float64{0.332}},
					{Flowid: 3, Rtt: []float64{0.329}},
					{Flowid: 4, Rtt: []float64{0.567}},
					{Flowid: 5, Rtt: []float64{0.329}},
					{Flowid: 6, Rtt: []float64{1.237}},
				},
			},
		},
	}
	if err != nil {
		t.Fatalf("Err during json parsing %v", err)
	}
	if output.UUID != "ndt-plh7v_1566050090_000000000004D60F" {
		t.Fatalf("Wrong results for UUID parsing!")
	}
	if output.ServerIP != "2001:550:1b01:1:e41d:2d00:151:f6c0" || output.ClientIP != "2600:1009:b013:1a59:c369:b528:98fd:ab43" {
		t.Fatalf("Wrong results for source/destination IP parsing!")
	}
	if output.ProbeSize != 60 || output.ProbeC != 85 {
		t.Fatalf("Wrong results for probe size or probec parsing!")
	}
	if !reflect.DeepEqual(output.Hop[0], expectedHop) {
		fmt.Printf("Here is expected    : %+v\n", expectedHop)
		fmt.Printf("Here is what is real: %+v\n", output.Hop[0])
		t.Fatalf("Wrong results for Json hops parsing!")
	}
}
func TestJSONParser(t *testing.T) {
	rawData, err := ioutil.ReadFile("testdata/20190927T070859Z_ndt-qtfh8_1565996043_0000000000003B64.jsonl")
	if err != nil {
		t.Fatalf(err.Error())
		return
	}
	ptTest, err := parser.ParseJSON("20190927T070859Z_ndt-qtfh8_1565996043_0000000000003B64.jsonl", []byte(rawData))
	if err != nil {
		t.Fatalf(err.Error())
	}
	if ptTest.UUID != "ndt-qtfh8_1565996043_0000000000003B64" {
		t.Fatalf("UUID parsing error %s", ptTest.UUID)
	}
}
