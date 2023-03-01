#!/bin/bash


##
# test is
# 1. create a non TPM key (pub and priv)
# 2. create a self signed cert with the key
# 3. verify the cert
#
# The purpose of the test is to ensure that non TPM keys still work 
# correctly when the engine is enabled (the engine should only bind
# to TPM keys).
##
for alg in "EC -pkeyopt ec_paramgen_curve:prime256v1" "RSA -pkeyopt rsa_keygen_bits:2048"; do
    openssl genpkey -algorithm ${alg} > key.priv && \
    openssl req -new -x509 -subj '/CN=test/' -key key.priv -engine tpm2 -out tmp.crt && \
    openssl verify -CAfile tmp.crt -engine tpm2 -check_ss_sig tmp.crt || \
    exit 1
done
