#!/bin/bash


##
# test is
# 1. Create an openssl private key and self signed cert in pkcs12 bag
# 2. Wrap the pkcs12 to an internal TPM private key
# 3. create a new non CA cert with key and sign it with the TPM private key
# 4. verify the signature

openssl ecparam -genkey -name prime256v1 > tmp.param || exit 1
openssl genpkey -paramfile tmp.param -out key.priv || exit 1
# warning: openssl 3.2 bug; subshell execution with standard openssl.cnf
# to work around
(
    unset OPENSSL_CONF
    openssl req -new -x509 -subj '/CN=test CA/' -key key.priv --extensions v3_ca -out tmp.crt || exit 1
    openssl pkcs12 -out tmp.p12 -passout pass: -export -inkey key.priv -in tmp.crt
)

${bindir}/create_tpm2_key -w tmp.p12 key.tpm || exit 1

openssl req -new -newkey rsa:2048 -keyout key1.priv -subj '/CN=test intermediate/' -out tmp1.csr -nodes || exit 1
openssl x509 -req -in tmp1.csr -CA tmp.crt -CAkey key.tpm $CAKEYFORM $ENGINE -set_serial 1 -out tmp1.crt -days 365 || exit 1

openssl verify -CAfile tmp.crt tmp1.crt || exit 1
