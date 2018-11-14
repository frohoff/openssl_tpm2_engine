#!/bin/bash

bindir=${srcdir}/..

# export the parent key as a public key
prim=$(tsscreateprimary -ecc nistp256 -hi o -opem srk.pub | sed 's/Handle //') || exit 1
tssflushcontext -ha ${prim} || exit 1

# check an EC key with a cert and password
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out key.priv || exit 1
${bindir}/create_tpm2_key --import srk.pub --wrap key.priv -a -k passw0rd key.tpm || exit 1
openssl req -new -x509 -subj '/CN=test/' -key key.tpm -passin pass:passw0rd -engine tpm2 -keyform engine -out tmp.crt || exit 1
openssl verify -CAfile tmp.crt -check_ss_sig tmp.crt || exit 1

#check an RSA key with a cert and policy
openssl genrsa 2048 > key.priv || exit 1
${bindir}/create_tpm2_key --import srk.pub --wrap key.priv -a -k passw0rd -c policies/policy_authvalue.txt key.tpm || exit 1
openssl req -new -x509 -subj '/CN=test/' -key key.tpm -passin pass:passw0rd -engine tpm2 -keyform engine -out tmp.crt || exit 1
openssl verify -CAfile tmp.crt -check_ss_sig tmp.crt || exit 1

