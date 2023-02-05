FROM ubuntu:20.04
MAINTAINER u1f383

RUN apt-get update && \
    DEBAIN_FRONTEND=noninteractive apt-get install -qy xinetd

RUN useradd -m fullchain-buff
RUN chown -R root:root /home/fullchain-buff
RUN chmod -R 755 /home/fullchain-buff

CMD ["/usr/sbin/xinetd", "-dontfork"]