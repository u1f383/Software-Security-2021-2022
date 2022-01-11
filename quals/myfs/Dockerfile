FROM ubuntu:20.04
MAINTAINER u1f383

RUN apt-get update && \
    DEBAIN_FRONTEND=noninteractive apt-get install -qy xinetd libssl-dev

RUN useradd -m myfs
RUN chown -R root:root /home/myfs
RUN chmod -R 755 /home/myfs

CMD ["/usr/sbin/xinetd", "-dontfork"]