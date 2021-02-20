#define TSSINCLUDE(x) < TSS_INCLUDE/x >
#include TSSINCLUDE(tss.h)
#include TSSINCLUDE(tssresponsecode.h)
#include TSSINCLUDE(tssutils.h)
#include TSSINCLUDE(tssmarshal.h)
#include TSSINCLUDE(Unmarshal_fp.h)
#include TSSINCLUDE(tsscrypto.h)
#include TSSINCLUDE(tsscryptoh.h)

#define VAL(X)			X.val
#define VAL_2B(X, MEMBER)	X.b.MEMBER
#define VAL_2B_P(X, MEMBER)	X->b.MEMBER
