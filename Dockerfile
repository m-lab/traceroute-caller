FROM golang:1.12 as build
ADD . /go/src/github.com/m-lab/traceroute-caller
ENV GOARCH amd64
ENV CGO_ENABLED 0
ENV GOOS linux
WORKDIR /go/src/github.com/m-lab/traceroute-caller
RUN go get -v \
      -ldflags "-X github.com/m-lab/go/prometheusx.GitShortCommit=$(git log -1 --format=%h)" \
      .
RUN chmod -R a+rx /go/bin/traceroute-caller

FROM ubuntu:latest
# Install all the standard packages we need
RUN apt-get update && apt-get install -y python python-pip make iproute2 coreutils

RUN ls -l
RUN mkdir /source
ADD ./vendor/scamper/ /source
RUN chmod +x /source/scamper-cvs-20190113/configure
WORKDIR /source/scamper-cvs-20190113/
RUN ./configure
RUN make
RUN make install

RUN chmod 4755 /usr/local/bin/scamper

COPY --from=build /go/bin/traceroute-caller /

WORKDIR /

ENTRYPOINT ["/traceroute-caller"]
