FROM ubuntu:20.04
MAINTAINER u1f383

RUN apt-get update && \
    DEBAIN_FRONTEND=noninteractive apt-get install -qy xinetd libssl-dev

RUN useradd -m myfs
RUN chown -R myfs:myfs /home/myfs
RUN chmod -R 755 /home/myfs
COPY share /home/myfs/

RUN chown myfs:myfs /home/myfs/flag1.txt
RUN chown myfs:myfs /home/myfs/flag2.txt
USER myfs

CMD ["/home/myfs/run.sh"]