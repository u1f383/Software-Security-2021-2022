FROM ubuntu:20.04
MAINTAINER u1f383

RUN apt-get update && \
    DEBAIN_FRONTEND=noninteractive apt-get install -qy xinetd

RUN useradd -m got2win
RUN chown -R root:root /home/got2win
RUN chmod -R 755 /home/got2win

CMD ["/usr/sbin/xinetd", "-dontfork"]