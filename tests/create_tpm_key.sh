#!/bin/bash

bindir=${srcdir}/..

##
# The Intel tss currently fails with the null seed, so skip the test
#
# see https://github.com/intel/tpm2-tss/issues/1993
##
if [ "$TSSTYPE" = "Intel" ]; then
    TESTNULL=
else
    TESTNULL="-p null"
fi
##
# test is
# 1. create TPM internal private key
# 2. get the corresponding public key from the engine
# 3. encode a message using the TPM key
# 4. verify the message through the public key
for parent in "" "-p 81000001" "-p owner" "${TESTNULL}" "-p platform" "-p endorsement"; do
    echo "Handle: ${parent}"
    ${bindir}/create_tpm2_key ${parent} key0.tpm || exit 1
    openssl rsa -engine tpm2 -inform engine -in key0.tpm -pubout -out key0.pub || exit 1
    echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key0.tpm -out tmp.msg || exit 1
    openssl rsautl -verify -in tmp.msg -inkey key0.pub -pubin || exit 1
done

exit 0

