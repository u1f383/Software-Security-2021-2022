#!/bin/bash

set -e

sudo apt install xinetd
sudo cp xinetd /etc/xinetd.d/myfs
/usr/sbin/xinetd -dontfork &