#!/bin/bash
set -x

##
# First create a NV object and a permanent key with a known authorization
##
PASSWORD="RNDPWD${RANDOM}"
NVINDEX=0x01000002
NVKEY=0x81005555
DATA="Some Random Data ${RANDOM}"
tssnvdefinespace -hi o -ha ${NVINDEX} -pwdn ${PASSWORD} || exit 1
# note index is not initialized (but shouldn't need to be)
key=$(tsscreateprimary -hi o -st -ecc nistp256 -pwdk ${PASSWORD}|sed 's/Handle //') && \
tssevictcontrol -hi o -ho ${key} -hp ${NVKEY} && \
tssflushcontext -ha ${key}
# create a policy key
openssl genpkey -out policy.key -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 || exit 1
openssl pkey -in policy.key -pubout -out policy.pub

##
# Tests for each index, create an ordinary key a sealed object and a
# signed policy key each with --secret and then verify they fail with
# no password and accept the object password
##
for index in ${NVINDEX} ${NVKEY}; do

    ${bindir}/create_tpm2_key --secret ${index} key.tpm || exit 1
    echo ${DATA}|${bindir}/seal_tpm2_data --secret ${index} seal.tpm || exit 1
    echo ${DATA} > plain.txt
    openssl pkey $ENGINE $INFORM -in key.tpm -passin pass:" " -pubout -out key.pub || exit 1
    ${bindir}/create_tpm2_key --signed-policy policy.pub skey.tpm
    ${bindir}/signed_tpm2_policy add --policy-name "secret" --secret ${index} skey.tpm policy.key || exit 1
    openssl pkey $ENGINE $INFORM -in skey.tpm -passin pass:" " -pubout -out skey.pub || exit 1

    # Verify use without password fails

    openssl pkeyutl -sign -passin pass:" " -in plain.txt $ENGINE $KEYFORM -inkey key.tpm -out tmp.msg && exit 1
    ${bindir}/unseal_tpm2_data seal.tpm -k " " && exit 1
    openssl pkeyutl -sign -passin pass:" " -in plain.txt $ENGINE $KEYFORM -inkey skey.tpm -out tmp.msg && exit 1

    # verify use with object password works
    openssl pkeyutl -sign -passin pass:${PASSWORD} -in plain.txt $ENGINE $KEYFORM -inkey key.tpm -out tmp.msg && \
	openssl pkeyutl -verify -in plain.txt -sigfile tmp.msg -inkey key.pub -pubin || exit 1
    ${bindir}/unseal_tpm2_data seal.tpm -k ${PASSWORD}| grep -q "${DATA}" || exit 1
    openssl pkeyutl -sign -passin pass:${PASSWORD} -in plain.txt $ENGINE $KEYFORM -inkey skey.tpm -out tmp.msg && \
	openssl pkeyutl -verify -in plain.txt -sigfile tmp.msg -inkey skey.pub -pubin || exit 1
done

exit 0
