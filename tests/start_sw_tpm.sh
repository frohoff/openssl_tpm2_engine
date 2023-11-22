#!/bin/bash
set -x

# remove any prior TPM contents
rm -f NVChip h*.bin *.permall
if [ -x "${TPMSERVER}" ]; then
${TPMSERVER} > /dev/null 2>&1  &
else
${SWTPM} socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --tpmstate dir=`pwd` &
fi
pid=$!
echo ${pid} > tpm_server.pid
##
# This powers on the tpm and starts it
# then we derive the RSA version of the storage seed and
# store it permanently at handle 81000001 and flush the transient
##
a=0; while [ $a -lt 10 ]; do
    if [ ! -x "${TPMSERVER}" -a -x "${SWTPM_IOCTL}" ]; then
	${SWTPM_IOCTL} --tcp 127.0.0.1:2322 -i
    else
	tsspowerup
    fi
    if [ $? -eq 0 ]; then
	break;
    fi
    sleep 1
    a=$[$a+1]
done
if [ $a -eq 10 ]; then
    echo "Waited 10s for tpm_server to come up; exiting"
    exit 1
fi

tssstartup && \
key=$(tsscreateprimary -hi o -st -rsa|sed 's/Handle //') && \
tssevictcontrol -hi o -ho ${key} -hp 81000001 && \
tssflushcontext -ha ${key}

