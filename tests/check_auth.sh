#!/bin/bash

bindir=${srcdir}/..

##
# test is
# 1. create TPM internal private key
# 2. get the corresponding public key from the engine
# 3. encode a message using the TPM key
# 4. verify the message through the public key
${bindir}/create_tpm2_key -a -k passw0rd key2.tpm && \
openssl rsa -engine tpm2 -inform engine -pubin -in key2.tpm -pubout -out key2.pub && \
echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key2.tpm -passin pass:passw0rd -out tmp.msg && \
openssl rsautl -verify -in tmp.msg -inkey key2.pub -pubin

