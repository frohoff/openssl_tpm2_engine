#!/bin/bash
set -x

##
# test is
# Start without any TPM socket listener and check the correct
# failures of the commands
# 1. create_tpm2_key
# 2. openssl load real key but fail to connect to TPM

${bindir}/create_tpm2_key -p 81000001 tmp.tpm 2> tmp.txt
if [ $? -ne 1 ]; then
    # exit of anything other than one means either success or segfault
    exit 1
fi
cat tmp.txt
if [ "$TSSTYPE" = "IBM" ]; then
    grep -q 'TPM2_ReadPublic failed' tmp.txt || exit 1
    grep -q TSS_RC_NO_CONNECTION tmp.txt || exit 1
else
    grep -q 'Failed to connect' tmp.txt || exit 1
fi
##
# This is a real TPM key so the ASN.1 parses correctly
##
echo "-----BEGIN TSS2 PRIVATE KEY-----
MIICEgYGZ4EFCgEDoAMBAQECBEAAAAEEggEYARYAAQALAAIEYAAAABAAEAgAAAAA
AAEAmhZqBqBvWkQUQno1blrLz0PhzSiF1+Hs/9P57vm3IKt02XAsiXzfipso+uiq
UxECUc1zESO6XI5Qeo/3a2XNJMpJ9e2U7vsD/9TaNoA4yXQ3pDVRbyTQsKYv4QG9
+jPwWnaz8cw8JLJ3rIjVbrb2VXl6u7OtgWNBXpsUlrHQRopiOsnk9NNV5C7dwrct
/XOUr2sJBBAPKGBnb0KLO9IfyFBiet1Sn/eSIce5QrF4zPLnntqAJLHKRaVB95Lg
+MOQ1p5+ZiBun780FW7EHSbfgwunxU7FK5CkOb8GfO5b9fg+/MO6GoCh1F5psJTX
mLEkGQF1c9Myts4Cc+Zbu1g8vwSB4ADeACDpW/gnAcRnH0qn2VZ7W3jpPJKrYDbv
xxSr7wAuXopD6QAQ+gwemszEUlHXssutoiUbPcDwGZ7Iwb0wGNcK6CEKh9k1UECa
giDcPZ8AMVK3XWlqCK5jXWgwXyX3n5gqafHjW878HH8tkMbTzLVjsszodG6JIBT5
hWslwvPCknPRgkbo2GxXjaigVeameT/k1v3qn2hDSU/b70QcI1xeq0Uh5HeS5ok3
heJUXsSYKGCfbbobhWVno/dAc4sOXd7BwwdclWYkDoQOpqUPWb4QqIbuYYb1Ha6K
q1DxkJAF
-----END TSS2 PRIVATE KEY-----" > tmp.tpm
##
# conversion to public key doesn't actually contact the TPM
# so this should succeed
##
openssl pkey $ENGINE $INFORM -in tmp.tpm -pubout -out tmp.pub 2> tmp.txt
if [ $? -ne 0 ]; then
    echo "TPM key import failed with $?"
    cat tmp.txt
    exit 1
fi
##
# key operation does contact the TPM and should fail
##
echo "This is a message" |\
openssl pkeyutl -sign $ENGINE $KEYFORM -inkey tmp.tpm -out tmp.msg 2> tmp.txt
if [ $? -ne 1 ]; then
    echo "TPM key signing failed with $?"
    cat tmp.txt
    exit 1
fi
cat tmp.txt
if [ "$TSSTYPE" = "IBM" ]; then
    grep -q 'TPM2_StartAuthSession failed' tmp.txt || exit 1
    grep -q TSS_RC_NO_CONNECTION tmp.txt || exit 1
else
    grep -q 'Failed to connect' tmp.txt || exit 1
fi

rm -f tmp.tpm tmp.txt

