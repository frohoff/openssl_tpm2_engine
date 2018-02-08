a=$(which tpm_server)
if [ $? -ne 0 ]; then
    exit 1;
fi
# remove any prior TPM contents
rm -f NVChip h*.bin
${a} > /dev/null 2>&1  &
pid=$!
echo ${pid} > tpm_server.pid
##
# This powers on the tpm and starts it
# then we derive the RSA version of the storage seed and
# store it permanently at handle 81000001 and flush the transient
##
a=0; while [ $a -lt 10 ]; do
    tsspowerup
    if [ $? -eq 0 ]; then
	break;
    fi
    sleep 1
done
if [ $a -eq 10 ]; then
    echo "Waited 10s for tpm_server to come up; exiting"
    exit 1
fi

tssstartup && \
key=$(tsscreateprimary -hi o -st -rsa|sed 's/Handle //') && \
tssevictcontrol -hi o -ho ${key} -hp 81000001 && \
tssflushcontext -ha ${key}

