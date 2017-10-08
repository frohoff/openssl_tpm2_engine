#!/bin/bash

bindir=${srcdir}/..

##
# test is
# 1. create TPM internal private key
# 2. get the corresponding public key from the engine
# 3. encode a message using the TPM key
# 4. verify the message through the public key
${bindir}/create_tpm2_key key0.tpm && \
openssl rsa -engine tpm2 -inform engine -in key0.tpm -pubout -out key0.pub && \
echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key0.tpm -out tmp.msg && \
openssl rsautl -verify -in tmp.msg -inkey key0.pub -pubin

