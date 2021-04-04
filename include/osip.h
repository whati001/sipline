//
// Created by akarner on 4/4/21.
//

#ifndef SIPLINE_OSIP_H
#define SIPLINE_OSIP_H

/**
 * This code is taken from the original project source repository, link seen below
 * git: https://git.savannah.gnu.org/git/osip.git
 *
 * Unfortunately, the osip2 library includes to much stuff which is not needed for this project
 * Sipline does not need to kepp transaction infos or create messages.
 *
 * So we have sourced out everything need to get the libosipparser2 up and running without the osip2 lib
 * In addition, we only used the MINSIZE code, plain libc malloc and free calls instead of the customized ones
 *
 * The aim of this is to reduce the memory usage, with the full blown library, the process consumes around 1.4 MB
 * without heap allocation.
 * Which may sounds ridiculous, but is the system has only 4 MB left we need to save any MB we can :)
 */

#define OSIP_SUCCESS 0
#define OSIP_UNDEFINED_ERROR -1
#define OSIP_BADPARAMETER -2
#define OSIP_WRONG_STATE -3
#define OSIP_NOMEM -4
#define OSIP_SYNTAXERROR -5
#define OSIP_NOTFOUND -6
#define OSIP_API_NOT_INITIALIZED -7
#define OSIP_NO_NETWORK -10
#define OSIP_PORT_BUSY -11
#define OSIP_UNKNOWN_HOST -12
#define OSIP_DISK_FULL -30
#define OSIP_NO_RIGHTS -31
#define OSIP_FILE_NOT_EXIST -32
#define OSIP_TIMEOUT -50
#define OSIP_TOOMUCHCALL -51
#define OSIP_WRONG_FORMAT -52
#define OSIP_NOCOMMONCODEC -53
#define OSIP_RETRY_LIMIT -60

#ifndef osip_malloc
#define osip_malloc(S) malloc(S)
#endif
#ifndef osip_realloc
#define osip_realloc(P, S) realloc(P, S)
#endif
#ifndef osip_free
#define osip_free(P) \
      {                  \
        if (P != NULL) { \
          free(P);       \
        }                \
      }
#endif

/**
 * Allocate an osip_t element.
 * @param osip the element to allocate.
 */
int osip_init(osip_t **osip) {
    static int ref_count = 0;

    if (ref_count == 0) {
        ref_count++;
        /* load the parser configuration */
        parser_init();
    }

    *osip = (osip_t *) osip_malloc(sizeof(osip_t));

    if (*osip == NULL)
        return OSIP_NOMEM; /* allocation failed */

    memset(*osip, 0, sizeof(osip_t));

    return OSIP_SUCCESS;
}

/**
 * Free all resource in a osip_t element.
 * @param osip The element to release.
 */
void osip_release(osip_t *osip) {
    osip_free(osip);
}

#endif //SIPLINE_OSIP_H
