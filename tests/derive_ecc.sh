#!/bin/bash


##
# test is to check that the key derivation works
# 1. create TPM internal private key
# 2. create and openssl private key
# 3. verify that the key derived from the openssl public key and the
#    TPM private key is the same as that derived from the TPM public
#    key and the openssl private key
#
##
# There's a huge caveat for the stupidity of openssl 1.0.2: the
# generated keys cannot have generic parameters; they must be
# identified by the curve OID.  The reason is that deep within the
# derive peer key functions, openssl will perform a curve generator
# comparison, which it does by the ameth pointer.  The ameth pointer
# is either an optimised value for a known curve or a generic value
# for parameters.  Because the TPM engine takes care to preserve the
# curve ID, it's key has the optimised method.  The public key of the
# non-TPM curve *must* have the same method and openssl has many ways
# to lose this information
##

for curve in $(${bindir}/create_tpm2_key --list-curves); do
    if openssl ecparam -name ${curve} 2>&1 | egrep '(invalid|unknown) curve'; then
	continue
    fi
    echo "Checking curve ${curve} explicitly named"
    ${bindir}/create_tpm2_key -p 81000001 --ecc ${curve} key0.tpm || exit 1
    openssl pkey $ENGINE $INFORM -in key0.tpm -pubout -out key0.pub || exit 1
    #openssl ecparam -name ${curve} > key1.param
    #openssl genpkey -paramfile key1.param -out key1.priv || exit 1
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:${curve} -pkeyopt ec_param_enc:named_curve -out key1.priv || exit 1
    openssl pkey -in key1.priv -pubout -out key1.pub || exit 1
    # OK have two private and two public keys now generate two
    # derivations, one from key0.tpm and key1.pub and the other from
    # key1.priv and key0.pub.
    openssl pkeyutl -derive $ENGINE $KEYFORM -inkey key0.tpm -peerkey key1.pub -out derive.1 || exit 1
    openssl pkeyutl -derive -inkey key1.priv -peerkey key0.pub -out derive.2 || exit 1
    # if we got it right, both derivations should be the same
    cmp derive.1 derive.2 || exit 1
    
done
