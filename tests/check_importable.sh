#!/bin/bash


# export the parent key as a public key
prim=$(tsscreateprimary -ecc nistp256 -hi o -opem srk.pub | sed 's/Handle //') || exit 1
tssflushcontext -ha ${prim} || exit 1

for n in sha1 sha256 sha384; do
    echo "Checking Name Hash $n"
    if [ "$n" = "sha256" ]; then
	POLICYFILE=${testdir}/policies/policy_pcr.txt
    else
	POLICYFILE=${testdir}/policies/policy_pcr${n}.txt
    fi
    # check an EC key with a cert and password
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out key.priv || exit 1
    ${bindir}/create_tpm2_key --import srk.pub --wrap key.priv -n ${n} -a -k passw0rd key.tpm || exit 1
    openssl req -new -x509 -subj '/CN=test/' -key key.tpm -passin pass:passw0rd -engine tpm2 -keyform engine -out tmp.crt || exit 1
    openssl verify -CAfile tmp.crt -check_ss_sig tmp.crt || exit 1

    # Check the loadability of an importable key
    NV=81000201
    ${bindir}/load_tpm2_key key.tpm ${NV} || exit 1
    openssl req -new -x509 -subj '/CN=test/' -key //nvkey:${NV} -passin pass:passw0rd -engine tpm2 -keyform engine -out tmp.crt || exit 1
    openssl verify -CAfile tmp.crt -check_ss_sig tmp.crt || exit 1
    tssevictcontrol -hi o -ho ${NV} -hp ${NV}

    #check an RSA key with a cert and policy
    openssl genrsa 2048 > key.priv || exit 1
    tsspcrreset -ha 16
    ${bindir}/create_tpm2_key --import srk.pub -n ${n} --wrap key.priv -c ${POLICYFILE} key.tpm || exit 1
    openssl req -new -x509 -subj '/CN=test/' -key key.tpm -engine tpm2 -keyform engine -out tmp.crt && exit 1
    tsspcrextend -ha 16 -ic aaa
    openssl req -new -x509 -subj '/CN=test/' -key key.tpm -engine tpm2 -keyform engine -out tmp.crt || exit 1
    openssl verify -CAfile tmp.crt -check_ss_sig tmp.crt || exit 1
done
