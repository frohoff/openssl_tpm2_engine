#!/bin/bash


for n in sha1 sha256 sha384; do
    echo "Checking Name Hash $n"
    ##
    # test is
    # 1. Verify that a standard key can't be unsealed
    # 2. seal a phrase
    # 3. recover the same phrase on unseal
    ##
    DATA="This is some DATA $n"
    AUTH="Passw0rd"
    ${bindir}/create_tpm2_key key.tpm || exit 1;
    ${bindir}/unseal_tpm2_data key.tpm 2> /dev/null && exit 1;
    echo $DATA | ${bindir}/seal_tpm2_data -n ${n} -a -k ${AUTH} seal.tpm || exit 1;
    ${bindir}/unseal_tpm2_data -k ${AUTH} seal.tpm | grep -q "${DATA}" || exit 1;

    ##
    # Check with policy
    # test is
    # 1. seal with a pcr lock and no auth
    # 2. verify unseal
    # 3. move PCR on and verify no unseal
    # 4. 1-3 with auth and pcr lock
    ##
    echo $DATA | ${bindir}/seal_tpm2_data -n ${n} --pcr-lock 2,16 seal.tpm || exit 1;
    ${bindir}/unseal_tpm2_data seal.tpm | grep -q "${DATA}" || exit 1;
    tsspcrextend -ha 16 -ic $RANDOM
    ${bindir}/unseal_tpm2_data seal.tpm && exit 1
    echo $DATA | ${bindir}/seal_tpm2_data -a -k ${AUTH} --pcr-lock 2,16 seal.tpm || exit 1;
    ${bindir}/unseal_tpm2_data -k ${AUTH} seal.tpm | grep -q "${DATA}" || exit 1;
    tsspcrextend -ha 16 -ic $RANDOM
    ${bindir}/unseal_tpm2_data -k ${AUTH} seal.tpm && exit 1

    ##
    # Check importable
    # test is
    # 1. create srk.pub as parent for import
    # 2. seal with password
    # 3. check unseal
    # 4. seal with policy
    # 5. check unseal
    # 6. update PCR and check unseal failure
    DATA="Some Different DATA $n"
    if [ "$n" = "sha256" ]; then
	POLICYFILE="${testdir}/policies/policy_pcr.txt"
    else
	POLICYFILE="${testdir}/policies/policy_pcr${n}.txt"
    fi
    ${bindir}/attest_tpm2_primary -C owner -n ${testdir}/eksign.name -f srk.pub || exit 1
    TPM_INTERFACE_TYPE= echo $DATA | ${bindir}/seal_tpm2_data -n ${n} -a -k ${AUTH} --import srk.pub seal.tpm || exit 1;
    ${bindir}/unseal_tpm2_data -k ${AUTH} seal.tpm | grep -q "${DATA}" || exit 1;
    rm seal.tpm

    TPM_INTERFACE_TYPE= echo $DATA | ${bindir}/seal_tpm2_data -n ${n} --import srk.pub --policy ${POLICYFILE} seal.tpm || exit 1;
    tsspcrreset -ha 16
    ${bindir}/unseal_tpm2_data -k ${AUTH} seal.tpm && exit 1
    tsspcrextend -ha 16 -ic aaa
    ${bindir}/unseal_tpm2_data -k ${AUTH} seal.tpm | grep -q "${DATA}" || exit 1;
    # check importable RSA (same data and policies)
    prim=$(tsscreateprimary -hi o -st -rsa -opem srk.pub | sed 's/Handle //') || exit 1
    tssflushcontext -ha $prim
    TPM_INTERFACE_TYPE= echo $DATA | ${bindir}/seal_tpm2_data -n ${n} -a -k ${AUTH} --parent 81000001 --import srk.pub seal.tpm || exit 1;
    ${bindir}/unseal_tpm2_data -k ${AUTH} seal.tpm | grep -q "${DATA}" || exit 1;
    rm seal.tpm

    TPM_INTERFACE_TYPE= echo $DATA | ${bindir}/seal_tpm2_data -n ${n} --import srk.pub --parent 81000001 --policy ${POLICYFILE} seal.tpm || exit 1;
    tsspcrreset -ha 16
    ${bindir}/unseal_tpm2_data -k ${AUTH} seal.tpm && exit 1
    tsspcrextend -ha 16 -ic aaa
    ${bindir}/unseal_tpm2_data -k ${AUTH} seal.tpm | grep -q "${DATA}" || exit 1;
done

exit 0
