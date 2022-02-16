#!/bin/bash

bindir=${srcdir}/..

##
# test is
# 1. create TPM internal private key with a password and da protection
# 2. loop trying to sign a message with the wrong password until lockout occurs
# 3. verify that correct password is still locked out
# 4. reset the tpm DA lock
# 5. verify that correct password works
${bindir}/create_tpm2_key --rsa --da -a -k passw0rd key.tpm || exit 1
count=1;
while true; do
    echo "This is a message" | 
    openssl pkeyutl -sign -engine tpm2 -keyform engine -inkey key.tpm -passin pass:passwrd -out tmp.msg 2>tmp.txt
    val=$?
    cat tmp.txt
    if [ $val -ne 1 ]; then
	echo "Sign with incorrect key returned $val"
	exit 1;
    fi
    if grep -q TPM_RC_LOCKOUT tmp.txt; then
	break;
    fi
    if grep -q "TPM is in DA lockout" tmp.txt; then
	break;
    fi

    # The TPM can return RETRY instead of AUTH_FAIL if it is still writing
    # the DA state to NV ram
    if [ "$TSSTYPE" = "IBM" ]; then
	grep -q TPM_RC_AUTH_FAIL tmp.txt || grep -q TPM_RC_RETRY tmp.txt|| exit 1
    else
	grep -q "HMAC check failed and DA counter incremented" tmp.txt || exit 1
    fi
    count=$[$count+1]
done
echo "Locked out after $count tries"
# try with correct password, should still be locked out
echo "This is a message" | 
openssl pkeyutl -sign -engine tpm2 -keyform engine -inkey key.tpm -passin pass:passw0rd -out tmp.msg 2>tmp.txt
val=$?
cat tmp.txt
if [ $val -ne 1 ]; then
    echo "Try with correct password did not fail correctly: $val"
    exit 1;
fi
if [ "$TSSTYPE" = "IBM" ]; then
    grep -q TPM_RC_LOCKOUT tmp.txt || exit 1
else
    grep -q "TPM is in DA lockout" tmp.txt || exit 1
fi
# clear the TPM DA (this would normally be password protected)
tssdictionaryattacklockreset
echo "This is a message" | 
openssl rsautl -sign -engine tpm2 -keyform engine -inkey key.tpm -passin pass:passw0rd -out tmp.msg || exit 1
