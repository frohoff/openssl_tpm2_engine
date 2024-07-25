#!/bin/bash
set -x

##
# We already created eksign.name and null.name, so check them first
##
${bindir}/attest_tpm2_primary --eksign --name ${testdir}/eksign.name || exit 1
${bindir}/attest_tpm2_primary --eksign --name ${testdir}/null.name && exit 1
${bindir}/attest_tpm2_primary --certify null --name ${testdir}/eksign.name ${testdir}/null.name || exit 1
##
# Run through certification of all the keys (already done null above
##
for h in owner endorsement platform; do
    rm -f tmp.name
    ${bindir}/attest_tpm2_primary -C ${h} -n ${testdir}/eksign.name -o > tmp.name || exit 1
    ${bindir}/attest_tpm2_primary -C ${h} -n ${testdir}/eksign.name tmp.name || exit 1
    ${bindir}/attest_tpm2_primary -C ${h} -n ${testdir}/eksign.name null.name && exit 1
done
##
# attestation tests
# 1. create both P-256 and RSA2048 attestation certs
##
openssl genrsa 2048 > ca.key || exit 1
# several EK templates exist, so try RSA and EC for each
for high in "" "-high"; do
    for alg in "-rsa 2048" "-ecc nistp256"; do
	tsscreateekcert ${high} ${alg} -cakey ca.key -of cert.der || exit 1
	${bindir}/attest_tpm2_primary --attest cert.der --name ${testdir}/eksign.name || exit 1
    done
done
