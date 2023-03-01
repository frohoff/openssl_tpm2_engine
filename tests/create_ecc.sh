#!/bin/bash


##
# test is
# 1. create TPM internal private key
# 2. Create a self signed x509 certificate
# 3. verify the certificate
for curve in $(${bindir}/create_tpm2_key --list-curves); do
    if openssl ecparam -name ${curve} 2>&1 | egrep '(invalid|unknown) curve'; then
	continue
    fi
    echo "Checking curve ${curve}"
    ${bindir}/create_tpm2_key -p 81000001 --ecc ${curve} key.tpm || \
    exit 1
    for hash in sha1 sha256 sha384; do
	openssl req -new -x509 -${hash} -subj '/CN=test/' -key key.tpm -engine tpm2 -keyform engine -out tmp.crt && \
	openssl verify -CAfile tmp.crt -check_ss_sig tmp.crt || \
	exit 1
    done
done
