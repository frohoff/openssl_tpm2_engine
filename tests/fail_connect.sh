#!/bin/bash
bindir=${srcdir}/..

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
grep -q 'TPM2_Create failed' tmp.txt || exit 1
grep -q TSS_RC_NO_CONNECTION tmp.txt || exit 1
##
# This is a real TPM key so the ASN.1 parses correctly
##
echo "
-----BEGIN TSS2 KEY BLOB-----
MIIB+AYFZ4EFCgKgAwEBAaEHAgUAgQAAAaKCARwEggEYARYAAQALAAIEYAAAABAA
EAgAAAAAAAEAwUMv8QpYlroIUt8aLUlVDWFkfm+qJszCF6pFa+u6346nd01LbRqh
uN+y6g8NghCuPzxS6kd8CbphFU9+0GwReK4656duHayx//u1EmStV3I522C/KiKL
c+sP9CfzvTmWDEonJZzEs8OXLqXCMrTKB3TlREDQxnslc5SNBgZcMkK4k2H7yRms
RIs0elCSdXxtfVn4Qw5VDYFzh4Hw0sCDoezsxa4AqGRbE7yscTCY5uOsVJ1kB7lY
DE5z5kTFMSnBLcQj98CoTmOg40UR6UZvCnD8iCgEz1ovLwmGoqyPzJior7/V90MT
0BQlIM0gq5FeB6LZupDrjxrYz6z1u+f60QSBwAC+ACD1Yd66z+2B6Vtr9vwfx+j0
ciT3n/lLOdLFEJT2pcrf4AAQWDWHQxUiSPF4NhcIsZUxb6MgNIudtIGuZDNIlpvl
pg9RqI0tA1DtJPyRSVNWvK9488KBdXa9rgHncDl5krAnsoA+k3B7hZyk8vPsKg6I
+F63KuxKXAUy9Vp+yx3q0+ShpuoAcaK/RLt/R6eryVqfu3V65kw654F/h4svx57u
eHE/E4MuHfTbmc56LxxPf7g5rNrGG+Aamu+DRg==
-----END TSS2 KEY BLOB-----
" > tmp.tpm
##
# conversion to public key doesn't actually contact the TPM
# so this should succeed
##
openssl rsa -engine tpm2 -inform engine -in tmp.tpm -pubout -out tmp.pub 2> tmp.txt
if [ $? -ne 0 ]; then
    echo "TPM key import failed with $?"
    cat tmp.txt
    exit 1
fi
##
# key operation does contact the TPM and should fail
##
echo "This is a message" |\
openssl rsautl -sign -engine tpm2 -keyform engine -inkey tmp.tpm -out tmp.msg 2> tmp.txt
if [ $? -ne 1 ]; then
    echo "TPM key signing failed with $?"
    cat tmp.txt
    exit 1
fi
cat tmp.txt
grep -q 'TPM2_Load failed' tmp.txt || exit 1
grep -q TSS_RC_NO_CONNECTION tmp.txt || exit 1

rm -f tmp.tpm tmp.txt

