#! /usr/bin/env bash

make
./crypto_dev_nodes.sh
insmod virtio_crypto.ko
