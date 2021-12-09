FROM ubuntu:20.04
MAINTAINER u1f383

ENV DEBIAN_FRONTEND=noninteractive
ENV LC_ALL=en_US.UTF-8

RUN apt update && \
    apt install -yq gcc && \
    apt install -yq gdb && \
    apt install -yq git && \
    apt install -yq ruby-dev && \
    apt install -yq vim-gtk3 && \
    apt install -yq fish && \
    apt install -yq glibc-source && \
    apt install -yq make && \
    apt install -yq gawk && \
    apt install -yq bison && \
    apt install -yq libseccomp-dev && \
    apt install -yq tmux && \
    apt install -yq wget && \
    apt install -yq locales && \
    locale-gen en_US.UTF-8

# compile glibc-2.31
RUN cd /usr/src/glibc && \
    tar xvf glibc-2.31.tar.xz && \
    mkdir glibc_dbg && \
    cd glibc_dbg && \
    ../glibc-2.31/configure --prefix $PWD --enable-debug && \
    make -j4

# install pwndbg
RUN git clone https://github.com/pwndbg/pwndbg ~/pwndbg && \
    cd ~/pwndbg && \
    ./setup.sh

# install pwngdb
RUN git clone https://github.com/scwuaptx/Pwngdb.git ~/Pwngdb && \
    cat ~/Pwngdb/.gdbinit >> ~/.gdbinit && \
    sed -i "s/source ~\/peda\/peda.py//g" ~/.gdbinit

RUN pip3 install pwntools==4.4.0
RUN gem install seccomp-tools one_gadget
RUN ln -s /usr/local/lib/python3.8/dist-packages/bin/ROPgadget /bin/ROPgadget

CMD ["/bin/fish"]