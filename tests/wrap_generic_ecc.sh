#!/bin/bash


##
# test is
# 1. create an EC private key with the curve parameters
# 2. wrap the private key to the TPM
# 3. Create a self signed x509 certificate
# 4. verify the certificate
for curve in $(${bindir}/create_tpm2_key --list-curves); do
    if openssl ecparam -name ${curve} 2>&1 | egrep '(invalid|unknown) curve'; then
	continue
    fi
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:${curve} -out key.priv && \
    ${bindir}/create_tpm2_key -p 81000001 -w key.priv key.tpm && \
    openssl req -new -x509 -subj '/CN=test/' -key key.tpm -engine tpm2 -keyform engine -out tmp.crt && \
    openssl verify -CAfile tmp.crt -check_ss_sig tmp.crt || \
    exit 1
done
