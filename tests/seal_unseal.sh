#!/bin/bash
set -x

bindir=${srcdir}/..

##
# test is
# 1. Verify that a standard key can't be unsealed
# 2. seal a phrase
# 3. recover the same phrase on unseal
##
DATA="This is some DATA"
AUTH="Passw0rd"
${bindir}/create_tpm2_key key.tpm || exit 1;
${bindir}/unseal_tpm2_data key.tpm 2> /dev/null && exit 1;
echo $DATA | ${bindir}/seal_tpm2_data -a -k ${AUTH} seal.tpm || exit 1;
${bindir}/unseal_tpm2_data -k ${AUTH} seal.tpm | grep -q "${DATA}" || exit 1;

exit 0
