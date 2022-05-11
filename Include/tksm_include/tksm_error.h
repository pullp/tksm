#ifndef _TKSM_ERROR_H_
#define _TKSM_ERROR_H_

#define TKSM_MK_ERROR(x)              (0x00100000|(x))

typedef enum _tksm_status_t {
    TKSM_SUCCESS                  = 0,

    TKSM_ERROR_UNEXPECTED         = TKSM_MK_ERROR(0x0001),      /* Unexpected error */
    TKSM_ERROR_INVALID_PARAMETER  = TKSM_MK_ERROR(0x0002),      /* The parameter is incorrect */
    TKSM_ERROR_OUT_OF_MEMORY       = TKSM_MK_ERROR(0x0003),      /* Out of memory */
    TKSM_ERROR_INVALID_QUOTE       = TKSM_MK_ERROR(0x0104),      /* Invalid quote */
} tksm_status_t;

#endif // _TKSM_ERROR_H_