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

## Traceroute Analyzer Tool: tranal

The `tranal` (rhymes with canal) command line tool in this repo can
analyze `scamper` MDA traceroutes that are in `.jsonl` format.  `tranal`
can do the following analysis on MDA traceroutes:

1. Extract single-path traceroutes from an MDA traceroute.
2. List traceroutes that took longer than a specified duration.
3. List complete and incomplete traceroutes.

Note:
* Not all traceroutes are complete.  That is, not all traceroutes
trace all the way to the destination IP address.
* By default, `tranal` only prints out single-paths that are complete.
To see everything, use the "-v" flag to enable verbose mode.
* Some hops are unresponsive and are shown as "*" in the output.
* There may be multiple replies from the same hop.  When showing
single-paths, only one reply is printed.  If you need to see all replies,
use the "-v" flag to enable verbose mode and see all replies.

The easiest way to get started with `tranal` is to first fetch an archive
of M-Lab's MDA traceroutes to analyze.  This can be done as shown below:

```sh
$ mkdir ~/traceroutes
$ cd ~/traceroutes
$ gsutil cp gs://archive-measurement-lab/ndt/scamper1/2021/10/01/20211001T003000.005106Z-scamper1-mlab1-lis02-ndt.tgz .
$ tar xzf 20211001T003000.005106Z-scamper1-mlab1-lis02-ndt.tgz 
```

The above command extracts individual traceroute files to a directory
called `2021`.  Now build the `tranal` tool as shown below:

```sh
$ git clone https://github.com/m-lab/traceroute-caller
$ cd traceroute-caller/cmd/tranal
$ go build
```

The above command builds `tranal` and now you can use it to analyze the
traceroute files that you extracted.  If `tranal` analyzes more than
one file, it prints statistics on how many files were found, how many
were skipped because they were not `.jsonl` files, how many errors, etc.


```sh
# Show usage message.
$ ./tranal -h
Usage: ./tranal [-cehv] [-d <seconds>] path [path...]
path  a pathname to a file or directory (if directory, all files are processed recursively)
-h    print usage message and exit
-c    print + and - in front of complete and incomplete traceroutes respectively
-d    print file names that took the specified duration or longer
-e    print examples how to use this tool and exit
-v    enable verbose mode

# Show examples.
$ ./tranal -e
Examples:
# Extract and print a single-path traceroute (if it exists) from a traceroute file
$ ./tranal ~/traceroutes/2021/10/01/20211001T002556Z_ndt-292jb_1632518393_0000000000051A0C.jsonl

2021/10/01/20211001T002556Z_ndt-292jb_1632518393_0000000000051A0C.jsonl
flowid: 1
TTL     RTT(ms) IP address
  0       0.000 2001:500d:200:3::139
  1       0.000 2001:500d:200:3::1
  2       6.510 2001:500d:100::2
  3       1.197 2001:4860:0:23::2
  4      43.398 2001:4860::9:4001:2751
  5      34.590 2001:4860::c:4000:d9ab
  6      33.923 2001:4860::c:4000:dd7a
  7      34.548 2607:f8b0:e000:8000::5
  8           * *
  9      33.530 2a00:1450:4009:817::2010  <=== destination

# Print all traceroute files in a directory hierarchy that took longer than 5 minutes
$ ./tranal -d 300 ~/traceroutes/2021
2021/10/01/20211001T000053Z_ndt-292jb_1632518393_00000000000516D4.jsonl: 428 seconds
2021/10/01/20211001T000151Z_ndt-292jb_1632518393_000000000005160D.jsonl: 386 seconds
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
$ ./tranal -c 2021    
 1 2021/10/01/20211001T000014Z_ndt-292jb_1632518393_00000000000516C8.jsonl
 1 2021/10/01/20211001T000015Z_ndt-292jb_1632518393_00000000000516C9.jsonl
-- 2021/10/01/20211001T000023Z_ndt-292jb_1632518393_00000000000516C4.jsonl
...

files found:                          425
files skipped (not .jsonl):             0
files that could not be read:           0
files that could not be parsed:         0
files successfully parsed:            425
files with no traceroute data:          0
files with complete traceroutes:      149  (35%)
```
