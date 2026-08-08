//
// Created by ash on 17/12/24.
//

#ifndef INKAY_INKAY_CONFIG_H
#define INKAY_INKAY_CONFIG_H

#ifdef __has_include
#if __has_include("inkay_config.local.h")

#include "inkay_config.local.h"
#define INKAY_CUSTOM 1

#endif
#endif

#ifndef NETWORK_BASEURL
#define NETWORK_BASEURL "pretendo.cc"
#endif

#ifndef WSC_ACCOUNT_HOST
#define WSC_ACCOUNT_HOST "account.pretendo.cc"
#endif

#ifndef KARAOKE_CONTROL_HOST
#define KARAOKE_CONTROL_HOST WSC_ACCOUNT_HOST
#endif

// Demae-Can Wii U channel replacement backend (see dns_hooks.cpp).
#ifndef DEMAECAN_HOST
#define DEMAECAN_HOST "demaecan." NETWORK_BASEURL
#endif

// Miiverse discovery endpoint (olv_urls.cpp). Defaults to Pretendo Network's
// real Miiverse; override to point at a self-hosted one instead. Must stay
// under 38 chars total (including "/v1/endpoint") - see olv_urls.h.
#ifndef MIIVERSE_DISCOVERY_URL
#define MIIVERSE_DISCOVERY_URL "discovery.olv." NETWORK_BASEURL "/v1/endpoint"
#endif

// BOSS (Background Online Storage Service) - SpotPass, tasksheets/policy
// files, standby-mode notification delivery (dns_hooks.cpp). Real Nintendo
// hosts are npdi.cdn.nintendo.net / npdl.cdn.nintendo.net /
// npfl.c.app.nintendo.net / nppl.app.nintendo.net / npts.app.nintendo.net /
// service.spr.app.nintendo.net.
#ifndef BOSS_NPDI_HOST
#define BOSS_NPDI_HOST "npdi." NETWORK_BASEURL
#endif
#ifndef BOSS_NPDL_HOST
#define BOSS_NPDL_HOST "npdl." NETWORK_BASEURL
#endif
#ifndef BOSS_NPFL_HOST
#define BOSS_NPFL_HOST "npfl." NETWORK_BASEURL
#endif
#ifndef BOSS_NPPL_HOST
#define BOSS_NPPL_HOST "nppl." NETWORK_BASEURL
#endif
#ifndef BOSS_NPTS_HOST
#define BOSS_NPTS_HOST "npts." NETWORK_BASEURL
#endif
#ifndef BOSS_SPR_HOST
#define BOSS_SPR_HOST "spr." NETWORK_BASEURL
#endif

// Call of Duty: Black Ops II - Demonware "ops2" connection/chat server
// (dns_hooks.cpp). Real host is ops2-wiiu-cs.prod.demonware.net.
#ifndef BO2_OPS2_CS_HOST
#define BO2_OPS2_CS_HOST "ops2-wiiu-cs." NETWORK_BASEURL
#endif

#endif //INKAY_INKAY_CONFIG_H
