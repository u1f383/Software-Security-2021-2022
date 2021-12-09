FROM ubuntu:20.04
MAINTAINER u1f383

RUN apt-get update && \
    DEBAIN_FRONTEND=noninteractive apt-get install -qy xinetd

RUN useradd -m rop2win
RUN chown -R root:root /home/rop2win
RUN chmod -R 755 /home/rop2win

CMD ["/usr/sbin/xinetd", "-dontfork"]