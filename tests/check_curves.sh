#!/bin/bash


##
# test is
# 1. make sure the --list-curves option works
# 2. list the ECC supported curves and check Unsupported doesn't appear
#
# This test will fail if executed on a TPM that supports a curve we don't
# have data for.  Email the bug list and ask for it to be added
##

$bindir/create_tpm2_key --list-curves || exit 1
$bindir/create_tpm2_key --list-curves | grep Unsupported && exit 1 || exit 0
