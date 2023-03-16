#!/bin/bash
set -x


##
# test is
# 1. create a no password key and move it to nvram at index 81232323
# 2. extract public part of key
# 3. verify a signature
# 4. same for a key with a password
# 5. same for key with a password and da implications
##
nvkey=81232323
auth=a4ffg6

tsscreate -rsa -gp -hp 81000001 -opr key.tpmpriv -opu key.tpmpub || exit 1
key=$(tssload -hp 81000001 -ipu key.tpmpub -ipr key.tpmpriv|sed 's/Handle //') || exit 1
tssevictcontrol -hi o -ho ${key} -hp ${nvkey} || exit 1
tssflushcontext -ha ${key}
openssl rsa $ENGINE $INFORM -pubin -in //nvkey:${nvkey} -pubout -out key1.pub || exit 1
echo "This is an internal key message" | openssl rsautl -sign $ENGINE $KEYFORM -inkey //nvkey:${nvkey} -out tmp.msg || exit 1
openssl rsautl -verify -in tmp.msg -inkey key1.pub -pubin || exit 1
tssevictcontrol -hi o -hp ${nvkey} -ho ${nvkey}

# now set a password
tsscreate -rsa -gp -hp 81000001 -pwdk ${auth} -opr key.tpmpriv -opu key.tpmpub || exit 1
key=$(tssload -hp 81000001 -ipu key.tpmpub -ipr key.tpmpriv|sed 's/Handle //') || exit 1
tssevictcontrol -hi o -ho ${key} -hp ${nvkey} || exit 1
tssflushcontext -ha ${key}

openssl rsa $ENGINE $INFORM -passin pass:${auth} -in //nvkey:${nvkey} -pubout -out key1.pub || exit 1
echo "This is an internal key message" | openssl rsautl -sign -passin pass:${auth} $ENGINE $KEYFORM -inkey //nvkey:${nvkey} -out tmp.msg || exit 1
openssl rsautl -verify -in tmp.msg -inkey key1.pub -pubin || exit 1
tssevictcontrol -hi o -hp ${nvkey} -ho ${nvkey}

# password plus DA implications
tsscreate -rsa -gp -hp 81000001 -pwdk ${auth} -da -opr key.tpmpriv -opu key.tpmpub || exit 1
key=$(tssload -hp 81000001 -ipu key.tpmpub -ipr key.tpmpriv|sed 's/Handle //') || exit 1
tssevictcontrol -hi o -ho ${key} -hp ${nvkey} || exit 1
tssflushcontext -ha ${key}
openssl rsa $ENGINE $INFORM -passin pass:${auth} -in //nvkey:${nvkey} -pubout -out key1.pub || exit 1
echo "This is an internal key message" | openssl rsautl -sign -passin pass:${auth} $ENGINE $KEYFORM -inkey //nvkey:${nvkey} -out tmp.msg || exit 1
openssl rsautl -verify -in tmp.msg -inkey key1.pub -pubin || exit 1
tssevictcontrol -hi o -hp ${nvkey} -ho ${nvkey}

# try with a different nvprefix
tsscreate -rsa -gp -hp 81000001 -opr key.tpmpriv -opu key.tpmpub || exit 1
key=$(tssload -hp 81000001 -ipu key.tpmpub -ipr key.tpmpriv|sed 's/Handle //') || exit 1
tssevictcontrol -hi o -ho ${key} -hp ${nvkey} || exit 1
tssflushcontext -ha ${key}

openssl rsa $ENGINE $INFORM -passin pass:${auth} -in //nvkey:${nvkey} -pubout -out key1.pub || exit 1
export NVPREFIX="wibble:"
echo "This is an internal key message" | openssl rsautl -sign -passin pass:${auth} $ENGINE $KEYFORM -inkey ${NVPREFIX}${nvkey} -out tmp.msg || exit 1
openssl rsautl -verify -in tmp.msg -inkey key1.pub -pubin || exit 1
tssevictcontrol -hi o -hp ${nvkey} -ho ${nvkey}

exit 0
