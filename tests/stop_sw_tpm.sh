#!/bin/bash 

kill -TERM $(cat tpm_server.pid) && \
rm tpm_server.pid
