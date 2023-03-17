#!/bin/bash



##
# test is
# 1. Create an openssl private key
# 2. Wrap it to a TPM internal private key in deprecated format
# 3. get the corresponding public key from the engine
# 4. encode a message using the TPM key
# 5. verify the message through the public key
##
openssl genrsa 2048 > key1.priv && \
    ${bindir}/create_tpm2_key --deprecated -a -k passw0rd -p 81000001 -w key1.priv key1.tpm && \
grep -e "-----BEGIN TSS2 KEY BLOB-----" key1.tpm && \
openssl rsa -engine tpm2 -inform engine -passin pass:passw0rd -in key1.tpm -pubout -out key1.pub && \
echo "This is another message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key1.tpm -passin pass:passw0rd -out tmp.msg && \
openssl rsautl -verify -in tmp.msg -inkey key1.pub -pubin
