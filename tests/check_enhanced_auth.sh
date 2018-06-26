#!/bin/bash

bindir=${srcdir}/..

tss_pcrreset_cmd=/usr/bin/tsspcrreset
tss_pcrextend_cmd=/usr/bin/tsspcrextend

if [ ! -e ${tss_pcrreset_cmd} ] || [ ! -e ${tss_pcrextend_cmd} ]; then
    echo "TSS utils not found, please specify the correct path."
    exit 1
fi

##
# test is
# 1. create TPM internal private key with PolicyAuthValue authorization
# 2. get the corresponding public key from the engine
# 3. encode a message using the TPM key
# 4. verify the message through the public key
${bindir}/create_tpm2_key -a -k passw0rd key2.tpm -c policies/policy_authvalue.txt && \
openssl rsa -engine tpm2 -inform engine -passin pass:passw0rd -in key2.tpm -pubout -out key2.pub && \
echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key2.tpm -passin pass:passw0rd -out tmp.msg && \
openssl rsautl -verify -in tmp.msg -inkey key2.pub -pubin

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
${bindir}/create_tpm2_key key2.tpm -c policies/policy_pcr.txt && \
openssl rsa -engine tpm2 -inform engine -in key2.tpm -pubout -out key2.pub && \
echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key2.tpm -out tmp.msg && \
openssl rsautl -verify -in tmp.msg -inkey key2.pub -pubin

##
# test is
# 1. reset PCR 16
# 2. create TPM internal private key with PolicyPCR authorization (should fail because PCR 16 does not have the correct value)
# 3. get the corresponding public key from the engine
# 4. encode a message using the TPM key
# 5. verify the message through the public key
${tss_pcrreset_cmd} -ha 16
${bindir}/create_tpm2_key key2.tpm -c policies/policy_pcr.txt
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
${tss_pcrreset_cmd} -ha 16
${tss_pcrextend_cmd} -ha 16 -ic aaa
${bindir}/create_tpm2_key -a -k passw0rd key2.tpm -c policies/policy_authvalue_pcr.txt && \
openssl rsa -engine tpm2 -inform engine -passin pass:passw0rd -in key2.tpm -pubout -out key2.pub && \
echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key2.tpm -passin pass:passw0rd -out tmp.msg && \
openssl rsautl -verify -in tmp.msg -inkey key2.pub -pubin

##
# test is
# 1. reset PCR 16
# 2. extend PCR 16 with 'aaa'
# 3. create TPM internal private key with PolicyPCR + PolicyAuthValue authorization
# 4. get the corresponding public key from the engine
# 5. encode a message using the TPM key
# 6. verify the message through the public key
${tss_pcrreset_cmd} -ha 16
${tss_pcrextend_cmd} -ha 16 -ic aaa
${bindir}/create_tpm2_key -a -k passw0rd key2.tpm -c policies/policy_pcr_authvalue.txt && \
openssl rsa -engine tpm2 -inform engine -passin pass:passw0rd -in key2.tpm -pubout -out key2.pub && \
echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key2.tpm -passin pass:passw0rd -out tmp.msg && \
openssl rsautl -verify -in tmp.msg -inkey key2.pub -pubin
