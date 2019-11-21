## build : docker build -t lightedge-upfservice .
## run :   docker run --net=host --rm --privileged -it lightedge-upfservice-

FROM ubuntu:18.04
MAINTAINER g.baggio@fbk.eu

ARG USER
ARG PASS

RUN echo $USER
RUN echo $PASS

RUN apt update
RUN apt install -y build-essential cmake autoconf
RUN apt install -y nano tcpdump net-tools iputils-ping git python python-pip iptables iproute2 netcat conntrack

RUN git clone https://github.com/kohler/click.git /click && cd /click && git checkout dabb6d61a28a0f350af93bc1f081dd913d8c8548
WORKDIR /click
RUN ./configure --disable-linuxmodule --enable-userlevel
RUN make
RUN make install

ADD install_vgtp.sh /
RUN /install_vgtp.sh $USER $PASS
RUN rm /install_vgtp.sh

WORKDIR /

ADD modes /modes
ADD launcher.sh /

# Run the launcher script
ENTRYPOINT ["/launcher.sh"]
