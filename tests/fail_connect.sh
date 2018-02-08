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
grep -q 'TPM2_ReadPublic failed' tmp.txt || exit 1
grep -q TSS_RC_NO_CONNECTION tmp.txt || exit 1
##
# This is a real TPM key so the ASN.1 parses correctly
##
echo "-----BEGIN TSS2 KEY BLOB-----
MIICFwYFZ4EFCgKgAwEBAaEGAgSBAAABooIBHASCARgBFgABAAsAAgRgAAAAEAAQ
CAAAAAAAAQDe92kKAADnax0VXfanY1VrsSAYyHudOVaFtkja8+JL3l4IMM4M19Wi
0q42V/yeqY1FTEgd4gO8pYDtDdYrxNGe1Z7Hl5JuZigXRUqtqR6KCmTLYxW+mwkD
iarJsZnYOawNtDDt4kQdV/saD9WbmX9NSsKA8/T256B7/AY9FWYtz8v41J/ZJfL1
Cs6y5LAe/HiJc+dODFjZsPSS/CgGeiEguUh8g11BdnDocrgsXZGzIhZYP/t1lZA9
AbfPAxf04Cj3NGd0kdLwCrNBbirMKXHuryPkBAKlvhseylFjZz39GjVh+wY745bc
FVwEV382mn6fvR3G5qqkdxPEUzFzJCePBIHgAN4AINHqRAW9YlEmDtMrKevZNgKT
N+FKyLR/dVBo0HT9BW6ZABD4tdfB5ZLkW5Seos7Ey8l0ov+yaOeBhARVovXR6tJG
21VdUo0n2Eauc1ehaZ6dFAoU7rpgID3UtfBfgLLEoymS44Y8xqLgpWMQLg7pHMic
JZ84jI3HuhPJTo4fDTeHf7aI/1uAfsPe0q0zzND5+cF2Maw6Wm6gsjAJsSoLD0MO
2vJiwPzr1X9f9PGbhlkciOj/IJRHiu423I4ymvFEVgKMVZg4BEpQBrWIWyMceVRx
QL4QAdW9Ac4kKt4=
-----END TSS2 KEY BLOB-----" > tmp.tpm
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

