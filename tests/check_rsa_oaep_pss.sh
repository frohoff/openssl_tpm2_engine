#!/bin/bash


openssl genrsa 2048 > key.priv || exit 1
openssl rsa -in key.priv -out key.pub -pubout || exit 1
${bindir}/create_tpm2_key --wrap key.priv -a -k passw0rd key.tpm || exit 1
echo "Checked encryption of OAEP PSS" > tmp.txt
openssl rsautl -encrypt -oaep -in tmp.txt -out tmp.msg -inkey key.pub -pubin || exit 1
openssl rsautl -decrypt -oaep -in tmp.msg -engine tpm2 -keyform engine -inkey key.tpm -passin pass:passw0rd || exit 1
##
# this PSS signature will be padded manually and done as an unpadded encrypt
# by the TPM
##
openssl sha256 -out tmp.md -binary tmp.txt || exit 1
openssl pkeyutl -sign -engine tpm2 -keyform engine -inkey key.tpm -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha256 -pkeyopt rsa_mgf1_md:sha256 -in tmp.md -out tmp.msg -passin pass:passw0rd || exit 1
# OpenSSL bug in some versions returns false for correct signature
openssl pkeyutl -verify -inkey key.pub -pubin -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha256 -pkeyopt rsa_mgf1_md:sha256 -in tmp.md -sigfile tmp.msg|grep 'Signature Verified Successfully'|| exit 1
##
# finally an OAEP encrypt which triggers an unpadded decrypt
##
openssl pkeyutl -encrypt -inkey key.pub -pubin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in tmp.txt -out tmp.msg || exit 1
openssl pkeyutl -decrypt -engine tpm2 -keyform engine -inkey key.tpm -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in tmp.msg -out recover.txt -passin pass:passw0rd || exit 1
diff -q tmp.txt recover.txt || exit 1

