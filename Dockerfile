FROM ubuntu:latest
MAINTAINER Ya Chang <yachang@google.com>
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
