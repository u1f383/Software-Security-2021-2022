FROM ubuntu:20.04
MAINTAINER u1f383

RUN apt-get update && \
    DEBAIN_FRONTEND=noninteractive apt-get install -qy xinetd

RUN useradd -m -d /home/<redacted> two-gadget
RUN chown -R root:root /home/<redacted>
RUN chmod -R 755 /home/<redacted>

CMD ["/usr/sbin/xinetd", "-dontfork"]