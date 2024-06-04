FROM ubuntu:20.04
MAINTAINER u1f383

RUN apt-get update && \
    DEBAIN_FRONTEND=noninteractive apt-get install -qy xinetd

RUN useradd -m sugar
RUN chown -R root:root /home/sugar
RUN chmod -R 755 /home/sugar

CMD ["/usr/sbin/xinetd", "-dontfork"]