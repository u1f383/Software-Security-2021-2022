FROM ubuntu:20.04
MAINTAINER u1f383

RUN apt-get update && \
    DEBAIN_FRONTEND=noninteractive apt-get install -qy xinetd

RUN useradd -m easyheap
RUN chown -R root:root /home/easyheap
RUN chmod -R 755 /home/easyheap

CMD ["/usr/sbin/xinetd", "-dontfork"]