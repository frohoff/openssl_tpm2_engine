#!/bin/bash


##
# test is
# 1. create an EC private key with the curve parameters
# 2. wrap the private key to the TPM
# 3. Create a self signed x509 certificate
# 4. verify the certificate
for curve in $(${bindir}/create_tpm2_key --list-curves); do
    if openssl ecparam -name ${curve} 2>&1 | egrep '(unknown|invalid) curve'; then
	continue
    fi
    echo "Checking curve ${curve}"
    openssl ecparam -param_enc named_curve -genkey -name ${curve} > tmp.param && \
    openssl genpkey -paramfile tmp.param -out key.priv && \
    ${bindir}/create_tpm2_key -p 81000001 -w key.priv key.tpm && \
    openssl req -new -x509 -subj '/CN=test/' -key key.tpm $ENGINE $KEYFORM -out tmp.crt && \
    openssl verify -CAfile tmp.crt -check_ss_sig tmp.crt || \
    exit 1
done
for curve in $(${bindir}/create_tpm2_key --list-curves); do
    if openssl ecparam -name ${curve} 2>&1 | egrep '(invalid|unknown) curve'; then
	continue
    fi
    echo "Checking curve ${curve}"
    openssl ecparam -param_enc explicit -genkey -name ${curve} > tmp.param && \
    openssl genpkey -paramfile tmp.param -out key.priv && \
    ${bindir}/create_tpm2_key -p 81000001 -w key.priv key.tpm && \
    openssl req -new -x509 -subj '/CN=test/' -key key.tpm $ENGINE $KEYFORM -out tmp.crt && \
    openssl verify -CAfile tmp.crt -check_ss_sig tmp.crt || \
    exit 1
done
