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
tsspowerup && \
tssstartup && \
key=$(tsscreateprimary -hi o -st -rsa|sed 's/Handle //') && \
tssevictcontrol -hi o -ho ${key} -hp 81000001 && \
tssflushcontext -ha ${key}

