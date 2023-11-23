#!/bin/bash
set -x
##
# The TPM emulators always run in locality 0, so the only tests
# we can do is create a key including and excluding locality zero
# and check that one loads and the other doesn't
##
LOCALITY_01234=0x1f
LOCALITY_1234=0x1e
echo "This is a message" > plain.txt
DATA="Test some data"

${bindir}/create_tpm2_key --ecc prime256v1 --locality ${LOCALITY_01234} key.tpm || exit 1
openssl pkeyutl -sign $ENGINE $KEYFORM -inkey key.tpm -in plain.txt -out tmp.msg|| exit 1
echo "${DATA}"|${bindir}/seal_tpm2_data --locality ${LOCALITY_01234} key.tpm
${bindir}/unseal_tpm2_data key.tpm|grep -q "${DATA}" || exit 1

${bindir}/create_tpm2_key --ecc prime256v1 --locality ${LOCALITY_1234} key.tpm || exit 1
openssl pkeyutl -sign $ENGINE $KEYFORM -inkey key.tpm -in plain.txt -out tmp.msg&& exit 1
echo "${DATA}"|${bindir}/seal_tpm2_data --locality ${LOCALITY_1234} key.tpm
${bindir}/unseal_tpm2_data key.tpm && exit 1

exit 0;
