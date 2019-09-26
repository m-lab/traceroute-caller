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
# Install all the standard packages we need and then remove the ap-get lists.
RUN apt-get update && \
    apt-get install -y python python-pip make iproute2 coreutils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN ls -l
RUN mkdir /source
ADD ./vendor/scamper/ /source
RUN chmod +x /source/scamper-cvs-20190916/configure
WORKDIR /source/scamper-cvs-20190916/
RUN ./configure
RUN make -j 8
RUN make install
RUN ldconfig

COPY --from=build /go/bin/traceroute-caller /

WORKDIR /

ENTRYPOINT ["/traceroute-caller"]
