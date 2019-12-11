# Build the traceroute-caller binary
FROM golang:1.13 as build
ADD . /go/src/github.com/m-lab/traceroute-caller
ENV GOARCH amd64
ENV CGO_ENABLED 0
ENV GOOS linux
WORKDIR /go/src/github.com/m-lab/traceroute-caller
RUN go get -v \
      -ldflags "-X github.com/m-lab/go/prometheusx.GitShortCommit=$(git log -1 --format=%h)" \
      .
RUN chmod -R a+rx /go/bin/traceroute-caller


# Build the binaries that are called by traceroute-caller
FROM ubuntu:latest
# Install all the packages we need and then remove the apt-get lists.
# iproute2 gives us ss
# all the other packages are for the build processes.
RUN apt-get update && \
    apt-get install -y iproute2 make coreutils autoconf libtool git build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build and install scamper
RUN ls -l
RUN mkdir /scamper-src
ADD ./vendor/scamper/ /scamper-src
RUN chmod +x /scamper-src/scamper-cvs-20190916/configure
WORKDIR /scamper-src/scamper-cvs-20190916/
RUN ./configure
RUN make -j 8
RUN make install
RUN ldconfig

# Build and install paris-traceroute
RUN mkdir /pt-src
ADD ./vendor/libparistraceroute/ /pt-src
WORKDIR /pt-src
RUN mkdir m4
RUN ./autogen.sh
RUN ./configure
RUN make -j 8
RUN make install
RUN ldconfig

# Bring the statically-linked traceroute-caller binary from the build image.
COPY --from=build /go/bin/traceroute-caller /

# Verify that all the binaries we depend on are actually available
RUN which paris-traceroute
RUN which scamper
RUN which sc_attach
RUN which sc_warts2json
RUN which ss

WORKDIR /
ENTRYPOINT ["/traceroute-caller"]
