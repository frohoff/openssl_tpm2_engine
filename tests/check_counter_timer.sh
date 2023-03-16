#!/bin/bash


##
# create a policy based on the tpm current clock the failing policy
# compares to current time and the passing one current time plus 10
# minutes (provided it doesn't take 10 minutes to get to the test)
##
# get current TPM clock value
clock=$(tssreadclock|awk '/TPMS_CLOCK_INFO clock/{print $3}')
# add 10 minutes in ms
clock=$[$clock + 600000]
# TPM_CC_PolicyAuthValue
echo "0000016b" > policy.txt
# the TPM_CC_PolicyCounterTimer
echo -n "0000016d" >> policy.txt
# time value as a 8 byte number
printf "%016x" $clock >> policy.txt
# the offset of the clock and the <= unsigned operator
echo "00080009" >> policy.txt

##
# test is
# 1. create TPM internal private key with PolicyCounterTimer
# 2. get the corresponding public key from the engine
# 3. encode a message using the TPM key
# 4. verify the message through the public key
##
echo "policy counter timer" > plain.txt
${bindir}/create_tpm2_key key.tpm -a -k paSSW0RD -c policy.txt && \
openssl rsa $ENGINE $INFORM -pubin -in key.tpm -pubout -out key.pub && \
openssl pkeyutl -sign -in plain.txt -passin pass:paSSW0RD $ENGINE $KEYFORM -inkey key.tpm -out tmp.msg && \
openssl pkeyutl -verify -in plain.txt -sigfile tmp.msg -inkey key.pub -pubin || exit 1

##
# advance the TPM clock by ten minutes and a second which should make
# the policy fail and try the same test again
##
echo "Advance clock to expire key"
clock=$[$clock+1000]
tssclockset -hi o -clock ${clock} || exit 1

##
# now the signing operation should fail
##
echo "Check key failure due to counter timer policy"
openssl pkeyutl -sign -in plain.txt -passin pass:paSSW0RD $ENGINE $KEYFORM -inkey key.tpm -out tmp.msg 2> tmp.txt && exit 1
# check we got the right failure message
grep "Policy Failure: Counter Timer at offset 8 is not <=" tmp.txt


