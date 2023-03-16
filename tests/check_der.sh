#!/bin/bash


##
# test is
# 1. create TPM internal private key
# 2. convert it to DER form
# 3. get the corresponding public key from the engine
# 4. encode a message using the TPM key
# 5. verify the message through the public key
${bindir}/create_tpm2_key -a -k passw0rd key2.tpm && \
openssl asn1parse -in key2.tpm -out key2.der && \
openssl rsa $ENGINE $INFORM -passin pass:passw0rd -in key2.der -pubout -out key2.pub && \
echo "This is a message" | openssl rsautl -sign $ENGINE $KEYFORM -inkey key2.der -passin pass:passw0rd -out tmp.msg && \
openssl rsautl -verify -in tmp.msg -inkey key2.pub -pubin

