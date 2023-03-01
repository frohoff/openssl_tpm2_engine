#ifdef HAVE_IBM_TSS
#include "ibm-tss.h"
#else
#ifdef HAVE_INTEL_TSS
#include "intel-tss.h"
#else
#error Unknown TSS
#endif
#endif
