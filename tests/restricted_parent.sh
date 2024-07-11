#!/bin/bash
set -x


NV=81000101
NV2=81000102

##
# basic restricted key creation tests for rsa, ecc both internal and wrapped
##
${bindir}/create_tpm2_key --restricted --rsa key.tpm || exit 1
${bindir}/create_tpm2_key --restricted --ecc prime256v1 key.tpm || exit 1
# now generate permanent wrapped keys for the NV indexes
openssl genrsa 2048 > keyrsa.priv || exit 1;
${bindir}/create_tpm2_key --restricted -w keyrsa.priv keyrsa.tpm || exit 1
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve -out keyecc.priv || exit 1
${bindir}/create_tpm2_key --restricted -w keyecc.priv keyecc.tpm || exit 1
##
# now lodge the RSA and EC parents at NV and NV2
##
${bindir}/load_tpm2_key keyrsa.tpm ${NV} || exit 1
${bindir}/load_tpm2_key keyecc.tpm ${NV2} || exit 1
##
# Using the already created RSA restricted wrapped key the tests are:
# 1. Load the restricted key into NV memory
# 2. parent a TPM internal key1 to the new NV key
# 3. generate a public key from key1
# 4. Sign and verify to prove key1 works
# 5. Clear the TPM, this renders all the existing keys unusable and
#    regenerates the storage primary seed
# 6. re-wrap the original private key to the new TPM and move it to NV
# 7. Sign and verify to prove key1 still works despite clearing the TPM.
##
for parent in ${NV2} ${NV}; do
    ${bindir}/create_tpm2_key -p ${parent} key.tpm || exit 1
    openssl rsa $ENGINE $INFORM -in key.tpm -pubout -out key.pub || exit 1
    echo "This is a test of moveable keys" | openssl rsautl -sign $ENGINE $KEYFORM -inkey key.tpm -out tmp.msg || exit 1
    openssl rsautl -verify -in tmp.msg -inkey key.pub -pubin || exit 1
done
# on exit key 1 is parented to ${NV}
tssclear -hi p || exit 1
${bindir}/create_tpm2_key --restricted -w keyrsa.priv keyrsa.tpm || exit 1
${bindir}/load_tpm2_key keyrsa.tpm ${NV} || exit 1

echo "This is a test of moveable keys" | openssl rsautl -sign $ENGINE $KEYFORM -inkey key.tpm -out tmp.msg || exit 1
openssl rsautl -verify -in tmp.msg -inkey key.pub -pubin || exit 1

##
# A few more tests of the load_tpm2_key command
# 1. check that a key with policy requires to be forced
# 2. check the use of parent auth to load the NV area
##
tssclear -hi p
${bindir}/create_tpm2_key --restricted -c ${testdir}/policies/policy_pcr.txt key2.tpm || exit 1
${bindir}/load_tpm2_key key2.tpm ${NV} && exit 1
${bindir}/load_tpm2_key --force key2.tpm ${NV} || exit 1

##
# now try to parent to a key with authorization
##
tssclear -hi p
${bindir}/create_tpm2_key --auth --password Passw0rd --restricted key2.tpm || exit 1
${bindir}/load_tpm2_key key2.tpm ${NV} || exit 1
${bindir}/create_tpm2_key --auth-parent Passw0rd --parent ${NV} key3.tpm || exit 1
${bindir}/load_tpm2_key --auth-parent Passw0rd key3.tpm ${NV2} || exit 1
##
# finally try importable keys.  At the moment these only work for ecc parents
##
tssclear -hi p
${bindir}/create_tpm2_key --restricted -w keyecc.priv keyecc.tpm || exit 1
${bindir}/load_tpm2_key keyecc.tpm ${NV2} || exit 1
openssl pkey $ENGINE $INFORM -in //nvkey:${NV2} -pubout -out keyecc.pub || exit 1
openssl genrsa 2048 > key.priv || exit 1
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve -out key1.priv
for key in key.priv key1.priv; do
    ${bindir}/create_tpm2_key --parent ${NV2} --import keyecc.pub --wrap ${key} key.tpm || exit 1
    openssl req -new -x509 -subj '/CN=test/' -key key.tpm $ENGINE $KEYFORM -out tmp.crt || exit 1
    openssl verify -CAfile tmp.crt -check_ss_sig tmp.crt || exit 1
done

##
# Now add back the RSA storage parent: clearing the TPM will have
# changed the storage seed and flushed it and it is needed to verify
# RSA importable keys
##
tssclear -hi p || exit 1
key=$(tsscreateprimary -hi o -st -rsa|sed 's/Handle //') && \
tssevictcontrol -hi o -ho ${key} -hp 81000001 && \
tssflushcontext -ha ${key}
