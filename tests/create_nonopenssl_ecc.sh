#!/bin/bash

# swtpm doesn't have a correct implementation of the Barreto-Naehrig curves
# which are the only openssl unparametrised ones, so skip the test
if [ ! -x "${TPMSERVER}" -a -x "${SWTPM}" ]; then
    exit 77;
fi

##
# test is
# create a private key with a non openssl curve
# 1. create two private tpm keys
# 2. get public keys from openssl for these (remember explicit)
# 3. derive a shared secret using priv1 and pub2
# 4. derive a shared secret using priv2 and pub1
# 5. check the secrets are identical
##


for curve in $(${bindir}/create_tpm2_key --list-curves); do
    if openssl ecparam -name ${curve} 2>&1 | egrep -v '(invalid|unknown) curve'; then
	continue
    fi
    echo "Checking curve ${curve}"
    ${bindir}/create_tpm2_key --ecc ${curve} key1.tpm || \
	exit 1
    openssl pkey $ENGINE $INFORM -in key1.tpm -pubout -out key1.pub || exit 1
    ${bindir}/create_tpm2_key --ecc ${curve} key2.tpm || \
	exit 1
    openssl pkey $ENGINE $INFORM -in key2.tpm -pubout -out key2.pub || exit 1
    openssl pkeyutl $ENGINE $KEYFORM -inkey key1.tpm -peerkey key2.pub -derive -out secret1.bin || exit 1
    openssl pkeyutl $ENGINE $KEYFORM -inkey key2.tpm -peerkey key1.pub -derive -out secret2.bin || exit 1
    diff -b secret1.bin secret2.bin || exit 1
done
