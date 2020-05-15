package parser_test

import (
	"io/ioutil"
	"log"
	"reflect"
	"strings"
	"testing"

	"github.com/m-lab/go/osx"
	"github.com/m-lab/traceroute-caller/parser"
	"github.com/m-lab/traceroute-caller/schema"
)

func TestInitParserVersion(t *testing.T) {
	ver := parser.InitParserVersion()
	if ver != "local development" {
		t.Errorf("Error in InitParserVersion")
	}

	defer osx.MustSetenv("RELEASE_TAG", "v1.1")()
	ver = parser.InitParserVersion()
	if ver != "https://github.com/m-lab/traceroute-caller/tree/v1.1" {
		t.Errorf("Error in InitParserVersion")
	}
}

func TestInitParserVersionCommit(t *testing.T) {
	defer osx.MustSetenv("RELEASE_TAG", "empty_tag")()
	defer osx.MustSetenv("COMMIT_HASH", "d6e45f1fff")()
	ver := parser.InitParserVersion()
	if ver != "https://github.com/m-lab/traceroute-caller/tree/d6e45f1f" {
		t.Errorf("Error in InitParserVersion")
	}
}

func TestGetLogtime(t *testing.T) {
	fn1 := parser.PTFileName{Name: "20160112T00:45:44Z_ALL27409.paris"}
	t1, err1 := parser.GetLogtime(fn1)
	if err1 != nil || t1.String() != "2016-01-12 00:45:44 +0000 UTC" {
		t.Errorf("Error in parsing log time from legacy filename!\n")
	}

	fn2 := parser.PTFileName{Name: "20170320T23:53:10Z-172.17.94.34-33456-74.125.224.100-33457.paris"}
	t2, err2 := parser.GetLogtime(fn2)
	if err2 != nil || t2.String() != "2017-03-20 23:53:10 +0000 UTC" {
		t.Errorf("Error in parsing log time from 5-tuple filename!\n")
	}

	fn3 := parser.PTFileName{Name: "20190908T000148Z_ndt-74mqr_1565960097_000000000006DBCC.jsonl"}
	t3, err3 := parser.GetLogtime(fn3)
	if err3 != nil || t3.String() != "2019-09-08 00:01:48 +0000 UTC" {
		t.Errorf("Error in parsing log time from scamper Json filename!\n")
	}

	fn4 := parser.PTFileName{Name: "traceroute[(64.86.132.76:33461)Random(98.162.212.214:5384.jsonl"}
	_, err4 := parser.GetLogtime(fn4)
	if err4 == nil {
		t.Errorf("Error in detecting wrong formatted filename")
	}
}

func TestParseFirstLine(t *testing.T) {
	protocol, dest_ip, server_ip, err := parser.ParseFirstLine("traceroute [(64.86.132.76:33461) -> (98.162.212.214:53849)], protocol icmp, algo exhaustive, duration 19 s")
	if dest_ip != "98.162.212.214" || server_ip != "64.86.132.76" || protocol != "icmp" || err != nil {
		t.Errorf("Error in parsing the first line!\n")
		return
	}

	protocol, dest_ip, server_ip, err = parser.ParseFirstLine("traceroute [(64.86.132.76:33461) -> (2001:0db8:85a3:0000:0000:8a2e:0370:7334:53849)], protocol icmp, algo exhaustive, duration 19 s")
	if dest_ip != "2001:0db8:85a3:0000:0000:8a2e:0370:7334" || server_ip != "64.86.132.76" || protocol != "icmp" || err != nil {
		t.Errorf("Error in parsing the first line!\n")
		return
	}

	protocol, dest_ip, server_ip, err = parser.ParseFirstLine("Exception : [ERROR](Probe.cc, 109)Can't send the probe : Invalid argument")
	if err == nil {
		t.Errorf("Should return error for err message on the first line!\n")
		return
	}

	protocol, dest_ip, server_ip, err = parser.ParseFirstLine("traceroute to 35.243.216.203 (35.243.216.203), 30 hops max, 30 bytes packets")
	if err == nil {
		t.Errorf("Should return error for unknown first line format!\n")
		return
	}

	protocol, dest_ip, server_ip, err = parser.ParseFirstLine("traceroute [(123:33461) -> (:53849)], protocol icmp, algo")
	if err == nil {
		t.Errorf("Should return error for unknown first line format!\n")
		return
	}

	protocol, dest_ip, server_ip, err = parser.ParseFirstLine("traceroute [(123:33461) -> (98.162.212.214:53849)], protocol icmp, algo")
	if err == nil {
		t.Errorf("Should return error for unknown first line format!\n")
		return
	}

	protocol, dest_ip, server_ip, err = parser.ParseFirstLine("traceroute [(64.86.132.76:33461) -> (98.162.212.214:53849)], protocol yyy, algo xxx, duration 19 s")
	if err == nil {
		t.Errorf("Should return error for unknown first line format!\n")
		return
	}

	protocol, dest_ip, server_ip, err = parser.ParseFirstLine("traceroute [(64.86.132.76:33461) -> (98.162.212.214:53849)], protocol icmp, algo xxx, duration 19 s")
	if err != nil {
		t.Errorf("algo could be something unknown and won't be an error!\n")
		return
	}
}

func TestCreateTestId(t *testing.T) {
	test_id := parser.CreateTestId("20170501T000000Z-mlab1-acc02-paris-traceroute-0000.tgz", "20170501T23:53:10Z-98.162.212.214-53849-64.86.132.75-42677.paris")
	if test_id != "2017/05/01/mlab1.acc02/20170501T23:53:10Z-98.162.212.214-53849-64.86.132.75-42677.paris.gz" {
		log.Println(test_id)
		t.Errorf("Error in creating test id!\n")
		return
	}
}

func TestPTParser(t *testing.T) {
	rawData, err := ioutil.ReadFile("testdata/20170320T23:53:10Z-172.17.94.34-33456-74.125.224.100-33457.paris")
	cachedTest, err := parser.Parse("", "testdata/20170320T23:53:10Z-172.17.94.34-33456-74.125.224.100-33457.paris", "", rawData)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if cachedTest.LogTime.Unix() != 1490053990 {
		t.Fatalf("Do not process log time correctly.")
	}

	if cachedTest.ServerIP != "172.17.94.34" {
		t.Fatalf("Wrong results for Server IP.")
	}

	if cachedTest.ClientIP != "74.125.224.100" {
		t.Fatalf("Wrong results for Client IP.")
	}

	// TODO(dev): reformat these individual values to be more readable.
	expected_hop := schema.ScamperHop{
		Source: schema.HopIP{
			IP:       "64.233.174.109",
			Hostname: "sr05-te1-8.nuq04.net.google.com",
		},
		Linkc: 0,
		Links: []schema.HopLink{
			schema.HopLink{
				HopDstIP: "74.125.224.100",
				TTL:      0,
				Probes: []schema.HopProbe{
					schema.HopProbe{
						Flowid: 0,
						Rtt:    []float64{0.895},
					},
				},
			},
		},
	}
	if len(cachedTest.Hops) != 38 {
		t.Fatalf("Wrong number of PT hops!")
	}

	if !reflect.DeepEqual(cachedTest.Hops[0], expected_hop) {
		log.Printf("Here is expected    : %v\n", expected_hop)
		log.Printf("Here is what is real: %v\n", cachedTest.Hops[0])
		t.Fatalf("Wrong results for PT hops!")
	}
}

func TestPTPollutionCheck(t *testing.T) {
	pt := &parser.PTParser{}

	tests := []struct {
		fileName             string
		expectedBufferedTest int
		expectedNumRows      int
	}{
		{
			fileName:             "testdata/20171208T00:00:04Z-35.188.101.1-40784-173.205.3.38-9090.paris",
			expectedBufferedTest: 1,
			expectedNumRows:      0,
		},
		{
			fileName: "testdata/20171208T00:00:04Z-37.220.21.130-5667-173.205.3.43-42487.paris",
			// The second test reached expected destIP, and was inserted into BigQuery table.
			// The buffer has only the first test.
			expectedBufferedTest: 1,
			expectedNumRows:      1,
		},
		{
			fileName: "testdata/20171208T00:00:14Z-139.60.160.135-2023-173.205.3.44-1101.paris",
			// The first test was detected that it was polluted by the third test.
			// expectedBufferedTest is 0, which means pollution detected and test removed.
			expectedBufferedTest: 0,
			// The third test reached its destIP and was inserted into BigQuery.
			expectedNumRows: 2,
		},
		{
			fileName: "testdata/20171208T00:00:14Z-76.227.226.149-37156-173.205.3.37-52156.paris",
			// The 4th test was buffered.
			expectedBufferedTest: 1,
			expectedNumRows:      2,
		},
		{
			fileName: "testdata/20171208T22:03:54Z-104.198.139.160-60574-163.22.28.37-7999.paris",
			// The 5th test was buffered too.
			expectedBufferedTest: 2,
			expectedNumRows:      2,
		},
		{
			fileName: "testdata/20171208T22:03:54Z-104.198.139.160-60574-163.22.28.37-8999.paris",
			// The 6th test was buffered. Due to buffer size limit, the 4th test was inserted into BigQuery and moved out of buffer.
			expectedBufferedTest: 2,
			expectedNumRows:      3,
		},
		{
			fileName: "testdata/20171208T22:03:59Z-139.60.160.135-1519-163.22.28.44-1101.paris",
			// The 5th test was detected that was polluted by the 7th test.
			// It was removed from buffer (expectedBufferedTest drop from 2 to 1).
			// Buffer contains the 4th test now.
			expectedBufferedTest: 1,
			// The 7th test reached its destIP and was inserted into BigQuery.
			expectedNumRows: 4,
		},
	}

	// Process the tests
	for _, test := range tests {
		rawData, err := ioutil.ReadFile(test.fileName)
		if err != nil {
			t.Fatalf("cannot read testdata.")
		}
		err = pt.ParseAndWrite(test.fileName, test.fileName, rawData)
		if err != nil {
			t.Fatalf(err.Error())
		}
		if pt.NumBufferedTests() != test.expectedBufferedTest {
			t.Fatalf("Data not buffered correctly for test " + test.fileName)
		}
		if pt.NumFilesForTests() != test.expectedNumRows {
			t.Fatalf("Data of test %s not inserted into BigQuery correctly. Expect %d Actually %d", test.fileName, test.expectedNumRows, pt.NumFilesForTests())
		}
	}
}

func TestParseAndWrite(t *testing.T) {
	pt := &parser.PTParser{}
	rawData := []byte(`traceroute to 35.243.216.203 (35.243.216.203), 30 hops max, 30 bytes packets`)
	err := pt.ParseAndWrite("", "testdata/20171208T22:03:54Z-104.198.139.160-60574-163.22.28.37-7999.paris", rawData)
	if err.Error() != "empty filename" {
		t.Fatal("fail to detect empty filename")
	}

	err = pt.ParseAndWrite("testdata/20171208T22:03:54Z-104.198.139.160-60574-163.22.28.37-7999.paris",
		"testdata/20171208T22:03:54Z-104.198.139.160-60574-163.22.28.37-7999.paris", rawData)
	if err.Error() != "Invalid data format in the first line." {
		t.Fatal("fail to detect corrupted file")
	}
}

func TestPTEmptyTest(t *testing.T) {
	rawData, err := ioutil.ReadFile("testdata/20180201T07:57:37Z-125.212.217.215-56622-208.177.76.115-9100.paris")
	if err != nil {
		t.Fatalf("cannot load test data")
	}
	_, parseErr := parser.Parse("", "testdata/20180201T07:57:37Z-125.212.217.215-56622-208.177.76.115-9100.paris", "", rawData)
	if parseErr == nil {
		t.Fatal("fail to detect empty test")
	}
}

func TestPTParserIllFormat(t *testing.T) {
	rawData := []byte(`traceroute to 35.243.216.203 (35.243.216.203), 30 hops max, 30 bytes packets`)
	_, parseErr := parser.Parse("", "testdata/20180201T07:57:37Z-125.212.217.215-56622-208.177.76.115-9100.paris", "", rawData)
	if parseErr == nil {
		t.Fatal("fail to detect corrupted first line")
	}

	_, parseErr = parser.Parse("", "testdata/xxx.paris", "", rawData)
	if parseErr == nil {
		t.Fatal("fail to parse the filename")
	}
}

func TestPTParserEmptyHop(t *testing.T) {
	rawData := []byte(`traceroute [(173.205.3.38:33458) -> (35.188.101.1:40784)], protocol icmp, algo exhaustive, duration 14 s
	1  P(6, 6) 172.17.95.252
	`)
	_, parseErr := parser.Parse("", "testdata/20180201T07:57:37Z-125.212.217.215-56622-208.177.76.115-9100.paris", "", rawData)
	if parseErr.Error() != "Empty test" {
		t.Fatal("fail to detect corrupted first line")
	}
}

func TestPTParserRttParsingFailure(t *testing.T) {
	rawData := []byte(`traceroute [(173.205.3.38:33458) -> (35.188.101.1:40784)], protocol icmp, algo exhaustive, duration 14 s
	1  P(6, 6) 172.17.95.252 (172.17.95.252)  xxxy ms
	`)
	_, parseErr := parser.Parse("", "testdata/20180201T07:57:37Z-125.212.217.215-56622-208.177.76.115-9100.paris", "", rawData)
	if parseErr.Error() != "Failed to parse rtts for icmp test. 4 numbers expected" {
		t.Fatal("fail to detect corrupted rtt value")
	}

	rawData = []byte(`traceroute [(172.17.94.34:33456) -> (74.125.224.100:33457)], protocol tcp, algo exhaustive, duration 3 s
	1  P(6, 6) 172.17.95.252 (172.17.95.252)  xxxy ms
	`)
	_, parseErr = parser.Parse("", "testdata/20180201T07:57:37Z-125.212.217.215-56622-208.177.76.115-9100.paris", "", rawData)
	if !strings.Contains(parseErr.Error(), "strconv.ParseFloat") {
		t.Fatal("fail to detect corrupted rtt value")
	}

	rawData = []byte(`traceroute [(173.205.3.38:33458) -> (35.188.101.1:40784)], protocol icmp, algo exhaustive, duration 14 s
	1  P(6, 6) 172.17.95.252 (172.17.95.252)  0.523 xxs
	`)
	_, parseErr = parser.Parse("", "testdata/20180201T07:57:37Z-125.212.217.215-56622-208.177.76.115-9100.paris", "", rawData)
	if parseErr.Error() != "Malformed line. Expected 'ms'" {
		t.Fatal("fail to detect corrupted rtt value")
	}

	rawData = []byte(`traceroute [(173.205.3.38:33458) -> (139.60.160.135:2023)], protocol icmp, algo exhaustive, duration 4 s
 1  P(6, 6) 173.205.3.1 (173.205.3.1)  0.168/5.683/xxxy/12.295 ms
 `)
	_, parseErr = parser.Parse("", "testdata/20180201T07:57:37Z-125.212.217.215-56622-208.177.76.115-9100.paris", "", rawData)
	if !strings.Contains(parseErr.Error(), "strconv.ParseFloat") {
		t.Fatal("fail to detect corrupted rtt value")
	}
}

func TestPTParserFlowFailure(t *testing.T) {
	rawData := []byte(`	traceroute [(172.17.94.34:33456) -> (74.125.224.100:33457)], protocol tcp, algo exhaustive, duration 3 s
 1  P(6, 6) 172.17.95.252 (172.17.95.252)  0.376 ms
 2  P(6, 6) us-mtv-cl4-core1-gigabitethernet1-1.n.corp.google.com (172.25.252.172)  0.407 ms
 3  P(6, 6) us-mtv-ply1-bb1-tengigabitethernet2-3.n.corp.google.com (172.25.252.166)  0.501 ms
 4  P(6, 6) us-mtv-ply1-br1-xe-1-1-0-706.n.corp.google.com (172.25.253.46)  0.343 ms
 5  P(16, 16) pr01-xe-7-1-0.pao03.net.google.com (72.14.218.190):0,2,3,4,xx,8,10  0.530 ms  pr02-xe-3-0-1.pao03.net.google.com (72.14.196.8):1,5,7,9  0.556 ms
 `)
	_, parseErr := parser.Parse("", "testdata/20180201T07:57:37Z-125.212.217.215-56622-208.177.76.115-9100.paris", "", rawData)
	if !strings.Contains(parseErr.Error(), "strconv.Atoi") {
		t.Fatal("fail to detect corrupted flow value")
	}

	rawData = []byte(`traceroute [(172.17.94.34:33456) -> (74.125.224.100:33457)], protocol tcp, algo exhaustive, duration 3 s
 1  P(6, 6) 172.17.95.252 (172.17.95.252)  0.376 ms
 2  P(6, 6) us-mtv-cl4-core1-gigabitethernet1-1.n.corp.google.com (172.25.252.172)  0.407 ms
 3  P(6, 6) us-mtv-ply1-bb1-tengigabitethernet2-3.n.corp.google.com (172.25.252.166)  0.501 ms
 4  P(6, 6) us-mtv-ply1-br1-xe-1-1-0-706.n.corp.google.com (172.25.253.46)  0.343 ms
 5  P(16, 16) pr01-xe-7-1-0.pao03.net.google.com (72.14.218.190):0,2,3,4,6,8,10:xxy  0.530 ms  pr02-xe-3-0-1.pao03.net.google.com (72.14.196.8):1,5,7,9  0.556 ms
 `)
	_, parseErr = parser.Parse("", "testdata/20180201T07:57:37Z-125.212.217.215-56622-208.177.76.115-9100.paris", "", rawData)
	if parseErr.Error() != "Wrong format for flow IP address" {
		t.Fatal("fail to detect corrupted flow value")
	}
}

func TestMiddleMessup(t *testing.T) {
	rawData := []byte(`traceroute [(172.17.94.34:33456) -> (74.125.224.100:33457)], protocol tcp, algo exhaustive, duration 3 s
	1  P(6, 6) 172.17.95.252 (172.17.95.252)  0.376 ms
	2  P(6, 6) us-mtv-cl4-core1-gigabitethernet1-1.n.corp.google.com (172.25.252.172)  0.407 ms
	3  P(6, 6) us-mtv-ply1-bb1-tengigabitethernet2-3.n.corp.google.com (172.25.252.166)  0.501 ms
	4  P(6, 6) us-mtv-ply1-br1-xe-1-1-0-706.n.corp.google.com (172.25.253.46)  0.343 ms
	5  P(6, 6) 74.125.224.100 (74.125.224.100)  0.895 ms
	6  P(16, 16) pr01-xe-7-1-0.pao03.net.google.com (72.14.218.190):0,2,3,4,6,8,10  0.530 ms  pr02-xe-3-0-1.pao03.net.google.com (72.14.196.8):1,5,7,9  0.556 ms
	7  P(16, 16) bb01-ae3.nuq04.net.google.com (216.239.49.250):0,2,3,4,6,8,10  1.386 ms  bb01-ae7.nuq04.net.google.com (72.14.232.136):1,5,7,9  1.693 ms
	8  P(6, 6) sr05-te1-8.nuq04.net.google.com (64.233.174.109)  1.614 ms
	`)
	_, parseErr := parser.Parse("", "testdata/20180201T07:57:37Z-125.212.217.215-56622-208.177.76.115-9100.paris", "", rawData)
	if parseErr != nil {
		t.Fatal("middle mess up should be just log warning, not create error")
	}
}
