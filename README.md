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

Start a local build using sample files in `./testdata`.

```sh
docker-compose up
```

After the docker images have started, trigger a network connection from
within one of those containers. For example:

```sh
docker exec -it $( docker ps | grep local-traceroute | awk '{print $1}' ) apt-get update
```

The logs from traceroute-caller should indicate that files are being saved
under `./local/*`.
