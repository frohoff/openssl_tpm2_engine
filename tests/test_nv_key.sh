#!/bin/bash


bindir=${srcdir}/..

##
# test is
# 1. create a key and move it to nvram at index 81232323
# 2. extract public part of key
# 3. verify a signature
##
nvkey=81232323
tsscreate -rsa -gp -hp 81000001 -opr key.tpmpriv -opu key.tpmpub || exit 1
key=$(tssload -hp 81000001 -ipu key.tpmpub -ipr key.tpmpriv|sed 's/Handle //') || exit 1

tssevictcontrol -hi o -ho ${key} -hp ${nvkey} || exit 1
tssflushcontext -ha ${key}
openssl rsa -engine tpm2 -inform engine -in //nvkey:${nvkey} -pubout -out key1.pub || exit 1
echo "This is an internal key message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey //nvkey:${nvkey} -out tmp.msg || exit 1
openssl rsautl -verify -in tmp.msg -inkey key1.pub -pubin || exit 1

exit 0
