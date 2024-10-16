# Build the traceroute-caller binary.
FROM golang:1.20 as build_caller
ADD . /go/src/github.com/m-lab/traceroute-caller
RUN rm /go/src/github.com/m-lab/traceroute-caller/Dockerfile
ENV CGO_ENABLED 0
ENV GOOS linux
WORKDIR /go/src/github.com/m-lab/traceroute-caller
RUN go get -v . && \
    go install -v -ldflags "-X github.com/m-lab/go/prometheusx.GitShortCommit=$(git log -1 --format=%h)" . && \
    chmod -R a+rx /go/bin/traceroute-caller

RUN go install -v ./cmd/generate-schemas && \
    chmod -R a+rx /go/bin/generate-schemas

# Build and install the tools that are called by traceroute-caller.
FROM ubuntu:22.04 as build_tracers
RUN apt-get update && \
    apt-get install -y make coreutils autoconf libtool git build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
# Build and install scamper.
RUN mkdir /scamper-src
ADD ./third_party/scamper/ /scamper-src
RUN tar xvzf  /scamper-src/scamper-cvs-20230302.tar.gz -C /scamper-src/
WORKDIR /scamper-src/scamper-cvs-20230302/
RUN chmod +x ./configure && \
    ./configure --prefix=/scamper && \
    make -j 8 &&  \
    make install

# Create an image for traceroute-caller and the tools that it calls.
FROM ubuntu:22.04
RUN apt-get update && \
    apt-get install -y libcap2-bin python3-pip tini && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
# Create /var/empty to avoid a race condition in scamper that results
# in the following failure:
#   scamper_privsep_init: could not mkdir /var/empty: File exists
RUN mkdir -p /var/empty && \
    chmod 555 /var/empty
# Copy the statically-linked traceroute-caller binary.
COPY --from=build_caller /go/bin/traceroute-caller /
COPY --from=build_caller /go/bin/generate-schemas /
# Copy the dynamically-linked scamper binary and its associated libraries.
COPY --from=build_tracers /scamper /usr/local

# Give the scamper binary all the needed capabilities so that the container
# processes can run as non-root.
#   DAC_OVERRIDE: Could not connect to "/var/local/tcpinfoeventsocket/tcpevents.sock" (error: dial unix /var/local/tcpinfoeventsocket/tcpevents.sock: connect: permission denied)
#   SYS_CHROOT: scamper_privsep_init: could not chroot to /var/empty: Operation not permitted
#   NET_RAW: to be able to talk ICMP
#   SETGID: scamper_privsep_init: could not setgroups: Operation not permitted
#   SETUID: scamper_privsep_init: could not setuid: Operation not permitted
RUN setcap cap_dac_override,cap_net_raw,cap_setgid,cap_setuid,cap_sys_chroot=ep /usr/local/bin/scamper

# Install fast-mda-traceroute from PyPI.
# We build pycaracal from source to avoid pulling precompiled binaries.
RUN pip3 install --upgrade pip wheel setuptools
RUN pip3 install --no-binary pycaracal --no-cache-dir --verbose fast-mda-traceroute==0.1.13

# Run ldconfig to locate all new libraries and verify the tools we need
# are available.
RUN ldconfig && \
    which scamper tini
WORKDIR /
# Make sure /traceroute-caller can run (has no missing external dependencies).
RUN /traceroute-caller -h 2> /dev/null
ENTRYPOINT ["tini", "--", "/traceroute-caller"]
