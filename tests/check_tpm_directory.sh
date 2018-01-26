#!/bin/bash

bindir=${srcdir}/..

printenv|grep dir

##
# test is
# 1. Generate a random key
# 2. create a read only directory and change to it
# 3. try to wrap the key
#
# note this test fails if the engine tries to write the TSS files to
# the current directory, so it's testing that we've correctly set
# TPM_DATA_DIR
##
$bindir/create_tpm2_key -p 81000001 -rsa -a -k passw0rd key.tpm || exit 1
mkdir testdir
chmod u-w testdir || exit 1
cd testdir || exit 1
echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey ../key.tpm -passin pass:passw0rd -out ../tmp.msg

