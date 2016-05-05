#include "server.h"
#include "redismodule.h"

#include <stdlib.h>
#include <sys/mman.h>

#include <security/pam_appl.h>

extern void authCommand(client *c);

static char *prev_requirepass;
static char prev_auth_prologue[32];       /* original authCommand code prologue before patching */

#ifdef __x86_64
static int patch_function(void *target_func, void *override_func,
        char *backup, int backup_len)
{
    int page_size = sysconf(_SC_PAGE_SIZE);
    unsigned long target_page_aligned = (unsigned long) target_func;
    target_page_aligned -= target_page_aligned % page_size;

    const char jmp_instr[] = {
        0xff, 0x25, 0x00, 0x00, 0x00, 0x00,                 /* jmpq *0x0(%rip) */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00      /* <addr> placeholder */
    };

    if (backup_len < sizeof(jmp_instr))
        return REDISMODULE_ERR;

    /* Unprotect target page */
    if (mprotect((void *)target_page_aligned, page_size, PROT_READ|PROT_WRITE|PROT_EXEC) < 0) {
        return REDISMODULE_ERR;
    }

    if (!override_func) {
        memcpy(target_func, backup, sizeof(jmp_instr));
    } else {
        memcpy(backup, target_func, sizeof(jmp_instr));
        memcpy(target_func, jmp_instr, sizeof(jmp_instr));
        memcpy((char *)target_func + 6, &override_func, sizeof(void *));
    }
    /* Restore protection */
    if (mprotect((void *)target_page_aligned, page_size, PROT_READ|PROT_EXEC) < 0) {
        return REDISMODULE_ERR;
    }
    return REDISMODULE_OK;
}
#else
#error Only x86_64 is currently supported, sorry.
#endif

/* PAM conversation handler.  We don't really want conversations with users
 * because we stick to the existing AUTH command, so we just try to detect
 * when we're asked for password and push it in.
 */
static int pam_conv_func(int num_msg, const struct pam_message **msg,
        struct pam_response **resp, void *appdata_ptr)
{
    int i;
    const struct pam_message *m;

    for (i = 0, m = *msg; i < num_msg; i++, m++) {
        if (strstr(m->msg, "assword") != NULL) {
            *resp = malloc(sizeof(struct pam_response));
            (*resp)->resp = strdup(appdata_ptr);
            break;
        }
    }
    return PAM_SUCCESS;
}

void override_authCommand(client *c)
{
    struct pam_conv pamc;
    pam_handle_t *pamh;
    int pam_err = 0;
    char remote_host[INET6_ADDRSTRLEN];

    int len;
    sds *credentials = sdssplitlen(c->argv[1]->ptr, sdslen(c->argv[1]->ptr), ":", 1, &len);

    if (len != 2) {
        addReplyError(c, "NOAUTH invalid credentials format");
        goto exit;
    }

    pamc.conv = &pam_conv_func;
    pamc.appdata_ptr = credentials[1];

    if (pam_start("redis", credentials[0], &pamc, &pamh) != PAM_SUCCESS)
        goto pam_error;

    anetPeerToString(c->fd, remote_host, sizeof(remote_host), NULL);
    if (pam_set_item(pamh, PAM_RHOST, remote_host) != PAM_SUCCESS)
        goto pam_error;

    if ((pam_err = pam_authenticate(pamh, 0)) != PAM_SUCCESS) {
        addReplyError(c, "NOAUTH invalid credentials");
    } else {
        addReplyStatus(c, "OK");
        c->authenticated = 1;
    }
    goto exit;

pam_error:
    addReplyError(c, "NOAUTH internal authentication error");

exit:
    sdsfreesplitres(credentials, len);
    pam_end(pamh, pam_err);
}

int RedisModule_OnLoad(RedisModuleCtx *ctx)
{
    if (RedisModule_Init(ctx, "pam_auth", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    /* Different ways to override a command:
     * 1. Use loadServerConfigFromString() to call 'rename-command' (not
     *    otherwise possible using CONFIG SET).  But Redis explicitly refers
     *    to authCommand() so this won't work.
     * 2. Manipulate server.commands.  More dirty than above, and won't work
     *    for the same reasons.
     * 3. Binary patching.  Can/should be done in a cleaner way, possibly using
     *    a dynamically generated trampoline so we can even resume execution of
     *    the original call.  For our POC, this is enough.
     */

    if (patch_function(authCommand, override_authCommand,
                prev_auth_prologue, sizeof(prev_auth_prologue)) ==
            REDISMODULE_ERR) return REDISMODULE_ERR;

    /* Mock up some requirepass so authentication is enforced */
    prev_requirepass = server.requirepass;
    if (server.requirepass) {
        zfree(server.requirepass);
    }

    /* We don't use requirepass but the Redis code base uses it as a flag to
     * determine AUTH is required.
     */
    server.requirepass = zstrdup("<pam_auth>");
    return REDISMODULE_OK;
}

void __attribute__((destructor)) OnUnload_Hack(void)
{
    zfree(server.requirepass);
    server.requirepass = prev_requirepass;

    patch_function(authCommand, NULL, prev_auth_prologue, sizeof(prev_auth_prologue));
}
