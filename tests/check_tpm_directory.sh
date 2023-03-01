#!/bin/bash


printenv|grep dir

##
# test is
# 1. Generate a random key
# 2. create a read only directory and change to it
# 3. try to wrap the key
#
# note this test fails if the engine tries to write the TSS files to
# the current directory, so it's testing that we've correctly set
# TPM_DATA_DIR
##
$bindir/create_tpm2_key -p 81000001 -rsa -a -k passw0rd key.tpm || exit 1
mkdir testdir
chmod u-w testdir || exit 1
cd testdir || exit 1
echo "This is a message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey ../key.tpm -passin pass:passw0rd -out ../tmp.msg
cd ..

##
# test is
# 1. obtain current user and group before running fakeroot
# 2. set XDG_RUNTIME_DIR_ env variables
# 3. Generate a random key
# 4. try to wrap the key (in background, suspend until there is data in fifo)
# 5. wait for tmp.msg to appear (created after lchown()) and check the owner and group
# 6. write data to fifo
# 7. evaluate owner and group of tss2. directory
#
# note this test fails if the tpm2 engine does not take into account the
# set XDG_RUNTIME_DIR_ env variables, owner and group would be root
##
cur_user=$(id -u -n -r)
cur_group=$(id -g -n -r)

fakeroot sh -c '

printenv|grep dir

export XDG_RUNTIME_DIR=$PWD
export XDG_RUNTIME_DIR_OWNER='$cur_user'
export XDG_RUNTIME_DIR_GROUP='$cur_group'
$bindir/create_tpm2_key -p 81000001 -rsa -a -k passw0rd key.tpm || exit 1
rm -f fifo
rm -f tmp.msg
mkfifo fifo || exit 1
cat fifo | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey key.tpm -passin pass:passw0rd -out tmp.msg &
pid=$!
while [ ! -f tmp.msg ] && [ -d /proc/$pid ]; do
    sleep 0.5
done

[ -d /proc/$pid ] || exit 1

owner=$(ls -ld $XDG_RUNTIME_DIR/tss2.* | awk "{print \$3}")
group=$(ls -ld $XDG_RUNTIME_DIR/tss2.* | awk "{print \$4}")
echo "This is a message" > fifo
wait
if [ $owner != '$cur_user' ] || [ $group != '$cur_group' ]; then
    exit 1
fi'
 [ $? -eq 0 ] || exit 1
