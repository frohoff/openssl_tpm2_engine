#!/bin/bash

tss_pcrreset_cmd=tsspcrreset
tss_pcrextend_cmd=tsspcrextend

if which ${tss_pcrreset_cmd} && which ${tss_pcrextend_cmd}; then
    :
else
    echo "TSS utils not found, please specify the correct path."
    exit 1
fi

DATA="This is some data to test"

for alg in EC RSA; do
    for h in sha1 "" sha384; do
	echo "Testing Name Parameter: ${h} and policy key algorithm ${alg}"
	if [ -n "${h}" ]; then
	    n="-n ${h}"
	else
	    n=""
	fi

	##
	# test is
	# 1. create a standard public/private key pair for policies
	# 2. create a tpm key with a signed policy
	# 3. verify the private part of the key is unusable (no policies)
	# 4. seal data with signed policy
	echo "This is a Message" > plain.txt
	if [ "$alg" = "EC" ]; then
	    openssl genpkey -out policy.key -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1
	else
	    openssl genpkey -out policy.key -algorithm RSA -pkeyopt rsa_keygen_bits:2048
	fi
	openssl pkey -in policy.key -pubout -out policy.pub
	${bindir}/create_tpm2_key ${n} --signed-policy policy.pub key.tpm || exit 1
	openssl pkeyutl -sign $ENGINE $KEYFORM -inkey key.tpm -in plain.txt -out tmp.msg && exit 1
	echo ${DATA} | ${bindir}/seal_tpm2_data --signed-policy policy.pub seal.tpm || exit 1
	${bindir}/unseal_tpm2_data seal.tpm && exit 1

	##
	# test is
	# 1. reset PCR 16
	# 2. extend PCR 16 with 'aaa'
	# 3. Add a four signed policy to the key with extensions of this PCR
	# 4. reset PCR 16
	# 5. do sign with key and verify four times.  Check that all
	#    but the last succeeds and the last one fails
	${tss_pcrreset_cmd} -ha 16
	${bindir}/signed_tpm2_policy add --policy-name "PCR16-0" --pcr-lock 16 key.tpm policy.key || exit 1
	${bindir}/signed_tpm2_policy add --policy-name "PCR16-0" --pcr-lock 16 seal.tpm policy.key || exit 1
	openssl rsa $ENGINE $INFORM -in key.tpm -pubout -out key.pub || exit 1
	${tss_pcrextend_cmd} -ha 16 -ic aaa
	${bindir}/signed_tpm2_policy add --policy-name "PCR16-extend" --pcr-lock 16 key.tpm policy.key || exit 1
	${bindir}/signed_tpm2_policy add --policy-name "PCR16-extend" --pcr-lock 16 seal.tpm policy.key || exit 1
	${tss_pcrextend_cmd} -ha 16 -ic aaa
	${bindir}/signed_tpm2_policy add --policy-name "PCR16-extendx2" --pcr-lock 16 key.tpm policy.key || exit 1
	${bindir}/signed_tpm2_policy add --policy-name "PCR16-extendx2" --pcr-lock 16 seal.tpm policy.key || exit 1
	${tss_pcrextend_cmd} -ha 16 -ic aaa
	${bindir}/signed_tpm2_policy add --policy-name "PCR16-extendx3" --pcr-lock 16 key.tpm policy.key || exit 1
	${bindir}/signed_tpm2_policy add --policy-name "PCR16-extendx3" --pcr-lock 16 seal.tpm policy.key || exit 1
	${tss_pcrreset_cmd} -ha 16
	openssl pkeyutl -sign -in plain.txt $ENGINE $KEYFORM -inkey key.tpm -out tmp.msg && \
	    openssl pkeyutl -verify -in plain.txt -sigfile tmp.msg -inkey key.pub -pubin || exit 1
	${bindir}/unseal_tpm2_data seal.tpm | grep -q "${DATA}" || exit 1
	${tss_pcrextend_cmd} -ha 16 -ic aaa
	openssl pkeyutl -sign -in plain.txt $ENGINE $KEYFORM -inkey key.tpm -out tmp.msg && \
	    openssl pkeyutl -verify -in plain.txt -sigfile tmp.msg -inkey key.pub -pubin || exit 1
	${bindir}/unseal_tpm2_data seal.tpm | grep -q "${DATA}" || exit 1
	${tss_pcrextend_cmd} -ha 16 -ic aaa
	openssl pkeyutl -sign -in plain.txt $ENGINE $KEYFORM -inkey key.tpm -out tmp.msg && \
	    openssl pkeyutl -verify -in plain.txt -sigfile tmp.msg -inkey key.pub -pubin || exit 1
	${bindir}/unseal_tpm2_data seal.tpm | grep -q "${DATA}" || exit 1
	${tss_pcrextend_cmd} -ha 16 -ic aaa
	openssl pkeyutl -sign -in plain.txt $ENGINE $KEYFORM -inkey key.tpm -out tmp.msg && \
	    openssl pkeyutl -verify -in plain.txt -sigfile tmp.msg -inkey key.pub -pubin || exit 1
	${bindir}/unseal_tpm2_data seal.tpm | grep -q "${DATA}" || exit 1
	${tss_pcrextend_cmd} -ha 16 -ic aaa
	openssl pkeyutl -sign -in plain.txt $ENGINE $KEYFORM -inkey key.tpm -out tmp.msg && exit 1
	${bindir}/unseal_tpm2_data seal.tpm && exit 1
	##
	# Finally check we can find the zero pcr16 policy in the list
	# and remove it
	##
	${tss_pcrreset_cmd} -ha 16
	${bindir}/signed_tpm2_policy ls seal.tpm | grep -q "4  PCR16-0" || exit 1
	${bindir}/signed_tpm2_policy rm seal.tpm 4 || exit 1
	${bindir}/signed_tpm2_policy ls seal.tpm | grep -q "  PCR16-0" && exit 1
	${bindir}/unseal_tpm2_data seal.tpm && exit 1
	${tss_pcrextend_cmd} -ha 16 -ic aaa
	${bindir}/unseal_tpm2_data seal.tpm || exit 1
    done
done
exit 0
