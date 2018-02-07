#!/bin/bash


bindir=${srcdir}/..

##
# test is
# 1. Create an openssl private key
# 2. Wrap it to a TPM internal private key
# 3. get the corresponding public key from the engine
# 4. encode a message using the TPM key
# 5. verify the message through the public key
##
openssl genrsa 2048 > key1.priv || exit 1;
for parent in "" "-p 81000001"; do
    ${bindir}/create_tpm2_key ${parent} -w key1.priv key1.tpm || exit 1
    openssl rsa -engine tpm2 -inform engine -in key1.tpm -pubout -out key1.pub || exit 1
    echo "This is another message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key1.tpm -out tmp.msg || exit 1
    openssl rsautl -verify -in tmp.msg -inkey key1.pub -pubin || exit 1
done

exit 0
