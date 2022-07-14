# traceroute-caller
[![Version](https://img.shields.io/github/tag/m-lab/traceroute-caller.svg)](https://github.com/m-lab/traceroute-caller/releases) [![Build Status](https://travis-ci.com/m-lab/traceroute-caller.svg?branch=master)](https://travis-ci.com/m-lab/traceroute-caller) [![Coverage Status](https://coveralls.io/repos/m-lab/traceroute-caller/badge.svg?branch=master)](https://coveralls.io/github/m-lab/traceroute-caller?branch=master) [![GoDoc](https://godoc.org/github.com/m-lab/traceroute-caller?status.svg)](https://godoc.org/github.com/m-lab/traceroute-caller) [![Go Report Card](https://goreportcard.com/badge/github.com/m-lab/traceroute-caller)](https://goreportcard.com/report/github.com/m-lab/traceroute-caller)

## Local Development

Using `docker-compose` you can run a local instance of traceroute-caller that
operates in concert with events from `measurementlab/tcpinfo` and using
annotation from `measurement-lab/uuid-annotator`.

You must have a recent version of the Docker server configured and running in
your local environment. As well, your local environment must include a recent
version of `docker-compose`.

```sh
$ docker-compose version
docker-compose version 1.27.4, build 40524192
docker-py version: 4.3.1
CPython version: 3.7.7
OpenSSL version: OpenSSL 1.1.1g  21 Apr 2020
```

In the root directory of traceroute-caller, start a local build using
sample files in `./testdata`.

```sh
docker-compose up
```

This will create and run three containers.  Container names are prefixed by the
current working directory name (i.e., traceroute-caller).  After the containers
are running, trigger a network connection from within one of those containers.
For example:

```sh
docker exec -it traceroute-caller_traceroute-caller_1 apt-get update
```

The logs from traceroute-caller should indicate that files are being saved
under `./local/*`.

```sh
ls -lR ./local
```

Use `docker-compose down` to stop the containers and remove resources before
restarting your docker-compose environment.

```sh
docker-compose down
docker-compose up
```

## Traceroute Examiner Tool: trex

The `trex` command line tool in this repo can examine `scamper` MDA
traceroutes that are in `.jsonl` format and do the following:

1. Extract single-path traceroutes from an MDA traceroute.
2. List traceroutes that took longer than a specified duration.
3. List complete and incomplete traceroutes.


Note:
* Not all traceroutes are complete.  That is, not all traceroutes
trace all the way to the destination IP address.
* Different hops associated with the same flow ID constitute a single path.
* The order of hops in a path is determined by the TTL.
* Unresponsive hops are marked as an asterisk ("*").
* It is possible for a hop to return multiple replies to a probe.
Therefore, for the same flow ID and TTL, there may be zero, one, or more
than one replies.
* When showing single-paths, only complete paths (if any) are printed.
* If you need to see all paths, use the "-v" flag to enable the verbose
mode.

The easiest way to get started with `trex` is to first fetch an archive
of M-Lab's MDA traceroutes to examine.  This can be done as shown below:

```sh
$ mkdir ~/traceroutes
$ cd ~/traceroutes
$ gsutil cp gs://archive-measurement-lab/ndt/scamper1/2021/10/01/20211001T003000.005106Z-scamper1-mlab1-lis02-ndt.tgz .
$ tar xzf 20211001T003000.005106Z-scamper1-mlab1-lis02-ndt.tgz
```

The above command extracts individual traceroute files to a directory
called `2021`.  Now build the `trex` tool as shown below:

```sh
$ git clone https://github.com/m-lab/traceroute-caller
$ cd traceroute-caller/cmd/trex
$ go build
```

The above command builds `trex` and now you can use it to examine the
traceroute files that you extracted.  If `trex` examines more than
one file, it prints statistics on how many files were found, how many
were skipped because they were not `.jsonl` files, how many errors, etc.


```sh
# Show usage message.
$ ./trex -h
Usage: ./trex [-cehv] [-d <seconds>] path [path...]
path  a pathname to a file or directory (if directory, all files are processed recursively)
-h    print usage message and exit
-c    print flow IDs and file names of traceroutes that completed ("--" for incomplete traceroutes)
-d    print times and file names of traceroutes that took more than the specified duration
-e    print examples how to use this tool and exit
-v    enable verbose mode (mostly for debugging)

# Show examples.
Examples:
# Extract and print a single-path traceroute (if it exists) from a traceroute file
$ trex /traceroutes/2022/04/01/20220401T001905Z_ndt-qqvlt_1647967485_000000000009379D.jsonl

file: /traceroutes/2022/04/01/20220401T001905Z_ndt-qqvlt_1647967485_000000000009379D.jsonl
src: 209.170.110.216
dst: 199.19.248.6
scamper start: 1648772345
tracelb start: 1648772345 (0 seconds after scamper start)
scamper stop:  1648772346 (1 seconds after scamper start)
flowid: 1
TTL    TX(ms)   RX(ms)    RTT(ms)  IP address
  1       N/A      N/A      0.000  209.170.110.193
  2       150      151      0.653  213.248.100.57
  3      1055     1062      7.244  199.19.248.6  <=== destination

The TX and RX columns are elapsed transmit and receive times since the tracelb
command was started.


# Same command as above but enable the verbose mode (useful for debugging).
$ trex -v /traceroutes/2022/04/01/20220401T001905Z_ndt-qqvlt_1647967485_000000000009379D.jsonl

/traceroutes/2022/04/01/20220401T001905Z_ndt-qqvlt_1647967485_000000000009379D.jsonl
Tracelb.Src: 209.170.110.216
Tracelb.Dst: 199.19.248.6
Tracelb.Nodes[0] 209.170.110.193
  Tracelb.Nodes[0].Links[0][0] 213.248.100.57
    Tracelb.Nodes[0].Links[0][0].Probes[0].Flowid: 1
    Tracelb.Nodes[0].Links[0][0].Probes[1].Flowid: 2
    Tracelb.Nodes[0].Links[0][0].Probes[2].Flowid: 3
    Tracelb.Nodes[0].Links[0][0].Probes[3].Flowid: 4
    Tracelb.Nodes[0].Links[0][0].Probes[4].Flowid: 5
    Tracelb.Nodes[0].Links[0][0].Probes[5].Flowid: 6
Tracelb.Nodes[1] 213.248.100.57
  Tracelb.Nodes[1].Links[0][0] 199.19.248.6
    Tracelb.Nodes[1].Links[0][0].Probes[0].Flowid: 1

file: /traceroutes/2022/04/01/20220401T001905Z_ndt-qqvlt_1647967485_000000000009379D.jsonl
src: 209.170.110.216
dst: 199.19.248.6
scamper start: 1648772345
tracelb start: 1648772345 (0 seconds after scamper start)
scamper stop:  1648772346 (1 seconds after scamper start)
flowid: 1
TTL    TX(ms)   RX(ms)    RTT(ms)  IP address
  1       N/A      N/A      0.000  209.170.110.193
  2       150      151      0.653  213.248.100.57
  3      1055     1062      7.244  199.19.248.6  <=== destination

flowid: 2
TTL    TX(ms)   RX(ms)    RTT(ms)  IP address
  1       N/A      N/A      0.000  209.170.110.193
  2       301      302      0.644  213.248.100.57

flowid: 3
TTL    TX(ms)   RX(ms)    RTT(ms)  IP address
  1       N/A      N/A      0.000  209.170.110.193
  2       452      453      0.707  213.248.100.57

flowid: 4
TTL    TX(ms)   RX(ms)    RTT(ms)  IP address
  1       N/A      N/A      0.000  209.170.110.193
  2       603      604      0.608  213.248.100.57

flowid: 5
TTL    TX(ms)   RX(ms)    RTT(ms)  IP address
  1       N/A      N/A      0.000  209.170.110.193
  2       754      754      0.621  213.248.100.57

flowid: 6
TTL    TX(ms)   RX(ms)    RTT(ms)  IP address
  1       N/A      N/A      0.000  209.170.110.193
  2       904      905      0.673  213.248.100.57


# Print all traceroute files in a directory hierarchy that took longer than 5 minutes
$ trex -d 300 /traceroutes/2021
 428 /traceroutes/2021/10/01/20211001T000053Z_ndt-292jb_1632518393_00000000000516D4.jsonl
 386 /traceroutes/2021/10/01/20211001T000151Z_ndt-292jb_1632518393_000000000005160D.jsonl
...

files found:                          425
files skipped (not .jsonl):             0
files that could not be read:           0
files that could not be parsed:         0
files successfully parsed:            425
files with no traceroute data:          0

minimum duration:                       4 seconds
maximum duration:                     456 seconds
average duration:                     220 seconds


# Print flow ID of complete traceroutes ("--" if incomplete) in a directory hierarchy
$ ./trex -c /traceroutes/2021
 1 /traceroutes/2021/10/01/20211001T000014Z_ndt-292jb_1632518393_00000000000516C8.jsonl
 1 /traceroutes/2021/10/01/20211001T000015Z_ndt-292jb_1632518393_00000000000516C9.jsonl
-- /traceroutes/2021/10/01/20211001T000023Z_ndt-292jb_1632518393_00000000000516C4.jsonl
...

files found:                          425
files skipped (not .jsonl):             0
files that could not be read:           0
files that could not be parsed:         0
files successfully parsed:            425
files with no traceroute data:          0
files with complete traceroutes:      149  (35%)
```
