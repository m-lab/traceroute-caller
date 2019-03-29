FROM golang:alpine as build
RUN apk update && apk add bash git pkgconfig geoip-dev geoip gcc libc-dev
ADD . /go/src/github.com/m-lab/traceroute-caller
RUN GOARCH=amd64 CGO_ENABLED=0 GOOS=linux go get github.com/m-lab/traceroute-caller
RUN chmod -R a+rx /go/bin/traceroute-caller

FROM ubuntu:latest
# Install all the standard packages we need
RUN apt-get update && apt-get install -y python python-pip make iproute2 coreutils

RUN ls -l
RUN mkdir /source
ADD . /go/src/github.com/m-lab/traceroute-caller
RUN mv /go/src/github.com/m-lab/traceroute-caller/vendor/scamper/scamper-cvs-20190113 /source
RUN chmod +x /source/scamper-cvs-20190113/configure
RUN /source/scamper-cvs-20190113/configure
RUN cd /source/scamper-cvs-20190113/
RUN ls -l /source/scamper-cvs-20190113/scamper
RUN make
RUN make install

RUN chmod 4755 /usr/local/bin/scamper

COPY --from=build /go/bin/traceroute-caller /

WORKDIR /

ENTRYPOINT ["/traceroute-caller"]
