## build : docker build -t lightedge-upfservice .
## run :   docker run --net=host --rm --privileged -it lightedge-upfservice

FROM ubuntu:18.04
MAINTAINER g.baggio@fbk.eu

RUN buildDeps='build-essential git cmake autoconf ca-certificates unzip' \
    && set -x \
    && apt-get update \
    && apt-get install -y $buildDeps --no-install-recommends \
    && apt-get install -y iptables iproute2 --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && git clone https://github.com/kohler/click.git click \
    && cd click \
    && git checkout dabb6d61a28a0f350af93bc1f081dd913d8c8548 \
    && ./configure --disable-linuxmodule --enable-userlevel \
    && make \
    && make install \
    && cd / \
    && rm -rf click \
    && git clone https://github.com/rriggio/upflib upflib \
    && cd upflib \
    && cmake -DCMAKE_BUILD_TYPE=Release \
             -DBUILD_SHARED_LIBS=OFF \
             -DCMAKE_INSTALL_PREFIX=/tmp/build \
    && make \
    && make install \
    && cd / \
    && git clone https://github.com/lightedge/lightedge-upfservice lightedge-upfservice \
    && cd lightedge-upfservice \
    && ./configure --with-click=/usr/local --with-upflib=/tmp/build \
    && make \
    && make install \
    && cd / \
    && rm -r /tmp/build \
    && rm -r /upflib \
    && rm -r /lightedge-upfservice \
    && apt-get purge -y --auto-remove $buildDeps

RUN ls /

ADD modes /modes
ADD launcher.sh /

# Run the launcher script
ENTRYPOINT ["/launcher.sh"]
