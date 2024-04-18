##
# common routines to be included
##

##
# check curve, returns 0 (success) for invalid curve so
#   if check_curve; then continue works
##
check_curve() {
    ##
    # if openssl supports sm2, it only allows sm3 as the hash, which
    # doesn't work with our generic tests, so skip it
    ##
    [ "${curve}" = "sm2" ] && return 0

    name=$(openssl ecparam -name $1 2>&1) || return 0
    echo $name|egrep '(invalid|unknown) curve' && return 0
    return 1
}
