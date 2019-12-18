# Build the traceroute-caller binary
FROM golang:1.13 as build_caller
ADD . /go/src/github.com/m-lab/traceroute-caller
RUN rm /go/src/github.com/m-lab/traceroute-caller/Dockerfile
ENV GOARCH amd64
ENV CGO_ENABLED 0
ENV GOOS linux
WORKDIR /go/src/github.com/m-lab/traceroute-caller
RUN go get -v \
      -ldflags "-X github.com/m-lab/go/prometheusx.GitShortCommit=$(git log -1 --format=%h)" \
      .
RUN chmod -R a+rx /go/bin/traceroute-caller


# Build the binaries that are called by traceroute-caller
FROM ubuntu:latest as build_tracers
# Install all the packages we need and then remove the apt-get lists.
# iproute2 gives us ss
# all the other packages are for the build processes.
RUN apt-get update && \
    apt-get install -y make coreutils autoconf libtool git build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build and install scamper
RUN ls -l
RUN mkdir /scamper-src
ADD ./vendor/scamper/ /scamper-src
RUN tar xvzf  /scamper-src/scamper-cvs-20191102a.tar.gz -C /scamper-src/
RUN chmod +x /scamper-src/scamper-cvs-20191102a/configure
WORKDIR /scamper-src/scamper-cvs-20191102a/
RUN ./configure --prefix=/scamper
RUN make -j 8
RUN make install

# Build and install paris-traceroute
RUN mkdir /pt-src
ADD ./vendor/libparistraceroute/ /pt-src
WORKDIR /pt-src
RUN mkdir -p m4
RUN ./autogen.sh
RUN ./configure --prefix=/paris-traceroute
RUN make -j 8
RUN make install

# Create an image for the binaries that are called by traceroute-caller without
# any of the build tools.
FROM ubuntu:latest
# Install all the packages we need and then remove the apt-get lists.
# iproute2 gives us ss
RUN apt-get update && \
    apt-get install -y iproute2 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Bring the statically-linked traceroute-caller binary from the go build image.
COPY --from=build_caller /go/bin/traceroute-caller /

# Bring the dynamically-linked traceroute binaries and their associated
# libraries from their build image.
COPY --from=build_tracers /scamper /usr/local
COPY --from=build_tracers /paris-traceroute /usr/local

# They are dynamically-linked, so make sure to run ldconfig to locate all new
# libraries.
RUN ldconfig

# Verify that all the binaries we depend on are actually available
RUN which paris-traceroute
RUN which scamper
RUN which sc_attach
RUN which sc_warts2json
RUN which ss

WORKDIR /
ENTRYPOINT ["/traceroute-caller"]
