#ifndef _PATCHER_H
#define _PATCHER_H

#include "../common/inkay_config.h"

typedef struct URL_Patch {
    unsigned int address;
    char url[80];
} URL_Patch;

static const URL_Patch url_patches[] = {
        //nim-boss .rodata
        // Do not redirect retired Pretendo shop/CDN hosts. They currently
        // return NXDOMAIN on public DNS resolvers, which makes NIM raise
        // 102-2106 before Wii Sports Club can reach the account proxy. By
        // omitting these addresses, IOSU keeps Nintendo's original URLs.
        {0xE229A0A0, "http://npns-dev.c.app.pretendo.cc/bst.dat"},
        {0xE229A0D0, "http://npns-dev.c.app.pretendo.cc/bst2.dat"},
        // nim-boss builds these requests from IOSU literals, bypassing the
        // game-process DNS hooks, so self-hosted BOSS needs direct URL patches.
        {0xE2299990, BOSS_NPPL_HOST},
        {0xE229A6AC, "https://npvk-dev.app.pretendo.cc/reports"},
        {0xE229A6D8, "https://npvk.app.pretendo.cc/reports"},
        {0xE229B1F4, "https://" BOSS_NPTS_HOST "/p01/tasksheet/%s/%s/%s/%s?c=%s&l=%s"},
        {0xE229B238, "https://" BOSS_NPTS_HOST "/p01/tasksheet/%s/%s/%s?c=%s&l=%s"},
        {0xE229DE0C, "n.app.pretendo.cc"},
        //nim-boss .bss
        {0xE24B8A24, "https://" BOSS_NPPL_HOST "/p01/policylist/1/1/UNK"},
        // The Wii U uses account API v1. Keep this URL fully literal: the
        // original IOSU format arguments can otherwise create a hostname that
        // is not covered by our DNS record. Extra variadic arguments passed to
        // snprintf are harmless when the format string has no conversions.
        {0xE31930D4, "https://" WSC_ACCOUNT_HOST "/v1/api/"}

};

#endif
