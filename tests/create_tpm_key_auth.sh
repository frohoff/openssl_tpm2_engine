#!/bin/bash


auth=4ffsiurh4

# change the authorization of the platform hierarchy
tsshierarchychangeauth -hi p -pwdn ${auth}
##
# test is
# 1. create TPM internal private key
# 2. get the corresponding public key from the engine
# 3. encode a message using the TPM key
# 4. verify the message through the public key
${bindir}/create_tpm2_key -p platform -b ${auth} key0.tpm || exit 1
openssl rsa -engine tpm2 -inform engine -in key0.tpm -pubout -out key0.pub || exit 1
# openssl has no way to specify the engine ctrl for the pin so we cheat
# and do it in the openssl.cnf file via an environment variable
export SRKPIN=${auth}
echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key0.tpm -out tmp.msg || exit 1
openssl rsautl -verify -in tmp.msg -inkey key0.pub -pubin || exit 1

tsshierarchychangeauth -hi p -pwda ${auth}

exit 0
