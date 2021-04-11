#!/bin/bash

bindir=${srcdir}/..

tss_pcrreset_cmd=tsspcrreset
tss_pcrextend_cmd=tsspcrextend

if which ${tss_pcrreset_cmd} && which ${tss_pcrextend_cmd}; then
    :
else
    echo "TSS utils not found, please specify the correct path."
    exit 1
fi

##
# check we can use a bogus policy 5 times without clogging up the TPM, so
# we're properly flushing policy handles
##
${bindir}/create_tpm2_key key.tpm -c policies/policy_bogus.txt
a=0; while [ $a -lt 5 ]; do
    a=$[$a+1]
    echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key.tpm -out tmp.msg && exit 1
done

##
# Randomize the PCR banks
##
for h in "sha1" "sha256" "sha384"; do
    pcr=0;
    while [ $pcr -le 24 ]; do
	tsspcrextend -ha $pcr -halg $h -ic $RANDOM
	pcr=$[$pcr + 1]
    done
    ##
    # reset PCR 16 for the fixed policy tests
    ##
    ${tss_pcrreset_cmd} -ha 16 -halg $h
done

for h in "sha1" "" "sha384"; do
    echo "Testing Name Parameter: ${h}"
    if [ -n "${h}" ]; then
	n="-n ${h}"
    else
	n=""
    fi
    ##
    # test is
    # 1. create TPM internal private key with PolicyAuthValue authorization
    # 2. get the corresponding public key from the engine
    # 3. encode a message using the TPM key
    # 4. verify the message through the public key
    ${bindir}/create_tpm2_key ${n} -a -k passw0rd key2.tpm -c policies/policy_authvalue.txt && \
    openssl rsa -engine tpm2 -inform engine -passin pass:passw0rd -in key2.tpm -pubout -out key2.pub && \
    echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key2.tpm -passin pass:passw0rd -out tmp.msg && \
    openssl rsautl -verify -in tmp.msg -inkey key2.pub -pubin || exit 1

    ##
    # test is
    # 1. reset PCR 16
    # 2. extend PCR 16 with 'aaa'
    # 3. create TPM internal private key with PolicyPCR authorization (PCR 16 extended with 'aaa')
    # 4. get the corresponding public key from the engine
    # 5. encode a message using the TPM key
    # 6. verify the message through the public key
    ${tss_pcrreset_cmd} -ha 16
    ${tss_pcrextend_cmd} -ha 16 -ic aaa
    ${bindir}/create_tpm2_key ${n} key2.tpm -c policies/policy_pcr${h}.txt && \
	openssl rsa -engine tpm2 -inform engine -in key2.tpm -pubout -out key2.pub && \
	echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key2.tpm -out tmp.msg && \
	openssl rsautl -verify -in tmp.msg -inkey key2.pub -pubin || exit 1

    ##
    # test is
    # 1. reset PCR 16
    # 2. create TPM internal private key with PolicyPCR authorization (should fail because PCR 16 does not have the correct value)
    # 3. get the corresponding public key from the engine
    # 4. encode a message using the TPM key
    # 5. verify the message through the public key
    ${tss_pcrreset_cmd} -ha 16
    ${bindir}/create_tpm2_key ${n} key2.tpm -c policies/policy_pcr${h}.txt
    openssl rsa -engine tpm2 -inform engine -in key2.tpm -pubout -out key2.pub && \
	echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key2.tpm -out tmp.msg && \
	openssl rsautl -verify -in tmp.msg -inkey key2.pub -pubin
    if [ $? -ne 1 ]; then
	echo "TPM key should not be accessible"
	exit 1
    fi

    ##
    # test is
    # 1. reset PCR 16
    # 2. extend PCR 16 with 'aaa'
    # 3. create TPM internal private key with PolicyAuthValue + PolicyPCR authorization
    # 4. get the corresponding public key from the engine
    # 5. encode a message using the TPM key
    # 6. verify the message through the public key
    cat policies/policy_authvalue.txt policies/policy_pcr${h}.txt > policy_authvalue_pcr.txt
    ${tss_pcrreset_cmd} -ha 16
    ${tss_pcrextend_cmd} -ha 16 -ic aaa
    ${bindir}/create_tpm2_key ${n} -a -k passw0rd key2.tpm -c policy_authvalue_pcr.txt && \
	openssl rsa -engine tpm2 -inform engine -passin pass:passw0rd -in key2.tpm -pubout -out key2.pub && \
	echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key2.tpm -passin pass:passw0rd -out tmp.msg && \
	openssl rsautl -verify -in tmp.msg -inkey key2.pub -pubin || exit 1

    ##
    # test is
    # 1. reset PCR 16
    # 2. extend PCR 16 with 'aaa'
    # 3. create TPM internal private key with PolicyPCR + PolicyAuthValue authorization
    # 4. get the corresponding public key from the engine
    # 5. encode a message using the TPM key
    # 6. verify the message through the public key
    cat policies/policy_pcr${h}.txt policies/policy_authvalue.txt > policy_pcr_authvalue.txt
    ${tss_pcrreset_cmd} -ha 16
    ${tss_pcrextend_cmd} -ha 16 -ic aaa
    ${bindir}/create_tpm2_key ${n} -a -k passw0rd key2.tpm -c policy_pcr_authvalue.txt && \
	openssl rsa -engine tpm2 -inform engine -passin pass:passw0rd -in key2.tpm -pubout -out key2.pub && \
	echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key2.tpm -passin pass:passw0rd -out tmp.msg && \
	openssl rsautl -verify -in tmp.msg -inkey key2.pub -pubin || exit 1

    ##
    # test is
    # 1. Create a key on a huge range of PCRs (testing multiple reads)
    # 2. verify key works with undisturbed PCRs
    # 3. extend non-mentioned pcr and verify key works
    # 4. extend mentioned PCR and verify key fails
    ##
    ${bindir}/create_tpm2_key ${n} -a -k passw0rd key.tpm --pcr-lock 1,2,3-15,17-23 --pcr-lock sha1:1-4 --pcr-lock sha384:10-20 || exit 1
    openssl rsa -engine tpm2 -inform engine -passin pass:passw0rd -in key.tpm -pubout -out key.pub || exit 1
    echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key.tpm -passin pass:passw0rd -out tmp.msg || exit 1
    openssl rsautl -verify -in tmp.msg -inkey key.pub -pubin || exit 1
    ${tss_pcrextend_cmd} -ha 16 -ic $RANDOM
    ${tss_pcrextend_cmd} -ha 5 -halg sha1 -ic $RANDOM
    ${tss_pcrextend_cmd} -ha 9 -halg sha384 -ic $RANDOM
    echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key.tpm -passin pass:passw0rd -out tmp.msg || exit 1
    openssl rsautl -verify -in tmp.msg -inkey key.pub -pubin || exit 1
    ${tss_pcrextend_cmd} -ha 1 -halg sha1 -ic $RANDOM
    echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key.tpm -passin pass:passw0rd -out tmp.msg && exit 1
    ##
    # Check a smaller PCR lock with no auth
    ##
    ${bindir}/create_tpm2_key ${n} --pcr-lock 2,4,7,10 --pcr-lock sha1:1,3 key.tpm || exit 1
    openssl rsa -engine tpm2 -inform engine -in key.tpm -pubout -out key.pub || exit 1
    echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key.tpm -out tmp.msg || exit 1
    openssl rsautl -verify -in tmp.msg -inkey key.pub -pubin || exit 1
    ${tss_pcrextend_cmd} -ha 4 -halg sha256 -ic $RANDOM
    echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key.tpm -out tmp.msg && exit 1
done

exit 0
