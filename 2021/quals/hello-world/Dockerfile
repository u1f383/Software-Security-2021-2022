FROM ubuntu:20.04
MAINTAINER u1f383

RUN apt-get update && \
    DEBAIN_FRONTEND=noninteractive apt-get install -qy xinetd

RUN useradd -m hello-world
RUN chown -R root:root /home/hello-world
RUN chmod -R 755 /home/hello-world

CMD ["/usr/sbin/xinetd", "-dontfork"]