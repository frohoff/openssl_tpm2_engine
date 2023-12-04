#!/bin/bash
set -x


# to work with the dynamic engine, we unset the openssl.cnf that
# specifies a built in engine
unset OPENSSL_CONF
export OPENSSL_ENGINES=${testdir}/../src/engine/.libs
ln -s libtpm2.so ${OPENSSL_ENGINES}/tpm2.so
export LD_LIBRARY_PATH=${OPENSSL_ENGINES}:{LD_LIBRARY_PATH}

testkey() {
    openssl pkey $ENGINE $INFORM -in key.tpm -pubout -out key.pub || exit 1
    # must be 32 bytes exactly for ECDSA signatures
    echo -n "12345678901234567890123456789012" > tmp.plain
    openssl pkeyutl -sign $ENGINE $KEYFORM -in tmp.plain -inkey key.tpm -out tmp.msg || exit 1
    openssl pkeyutl -verify -in tmp.plain -sigfile tmp.msg -inkey key.pub -pubin || exit 1
}

# check use of rsa key
${bindir}/create_tpm2_key --rsa key.tpm || exit 1

testkey

${bindir}/create_tpm2_key --ec prime256v1 key.tpm || exit 1

testkey

exit 0
