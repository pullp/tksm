#ifndef _FLAS_ERROR_H_
#define _FLAS_ERROR_H_

#define FLAS_MK_ERROR(x)              (0x00200000|(x))

typedef enum _flas_status_t {
    FLAS_SUCCESS                  = 0,

    FLAS_ERROR_UNEXPECTED         = FLAS_MK_ERROR(0x0001),      /* Unexpected error */
    FLAS_ERROR_INVALID_PARAMETER  = FLAS_MK_ERROR(0x0002),      /* The parameter is incorrect */
    FLAS_ERROR_OUT_OF_MEMORY       = FLAS_MK_ERROR(0x0003),      /* Out of memory */
    // FLAS_ERROR_INVALID_QUOTE       = FLAS_MK_ERROR(0x01÷04),      /* Invalid quote */
    FLAS_ERROR_LACK_OF_LOCAL_STATE = FLAS_MK_ERROR(0x0005),      /* Lack of local state */
    FLAS_ERROR_TOO_MUCH_LOCAL_STATE = FLAS_MK_ERROR(0x0005),      /* Lack of local state */
} flas_status_t;

#endif // _FLAS_ERROR_H_