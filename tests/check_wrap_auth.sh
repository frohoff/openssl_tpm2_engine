#!/bin/bash



##
# test is
# 1. Create an openssl private key
# 2. Wrap it to a TPM internal private key
# 3. get the corresponding public key from the engine
# 4. encode a message using the TPM key
# 5. verify the message through the public key
##
openssl genrsa 2048 > key1.priv && \
${bindir}/create_tpm2_key -a -k passw0rd -p 81000001 -w key1.priv key1.tpm && \
openssl rsa $ENGINE $INFORM -passin pass:passw0rd -in key1.tpm -pubout -out key1.pub && \
echo "This is another message" | openssl rsautl -sign $ENGINE $KEYFORM -inkey key1.tpm -passin pass:passw0rd -out tmp.msg && \
openssl rsautl -verify -in tmp.msg -inkey key1.pub -pubin
