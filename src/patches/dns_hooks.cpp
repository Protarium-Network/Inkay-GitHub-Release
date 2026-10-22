/*  Copyright 2024 Pretendo Network contributors <pretendo.network>
    Copyright 2024 Ash Logan <ash@heyquark.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <netdb.h>
#include <strings.h>

#include "config.h"
#include "utils/logger.h"
#include "inkay_config.h"
#include "bo2_auth.h"
#include "justdance_cert.h"
#include "Notification.h"
#include <array>
#include <vector>
#include <cstring>
#include <function_patcher/function_patching.h>

std::vector<PatchedFunctionHandle> dns_patches;

constexpr std::pair<const char *, const char *> dns_replacements[] = {
        // NNCS servers
        { "nncs1.app.nintendowifi.net", "nncs1.app." NETWORK_BASEURL },
        { "nncs2.app.nintendowifi.net", "nncs2.app." NETWORK_BASEURL },

        // Karaoke U / JOYSOUND Orchestra control service
        { "ssl.wahp.wah.wup.app.nintendo.net", KARAOKE_CONTROL_HOST },

        // Super Mario Maker fetches its 100 Mario Challenge course pool from
        // this HTTPS service rather than through NEX.
        { "wup-ama.app.nintendo.net", SMM_PICKUP_HOST },

        // Monster Hunter 3 Ultimate online/DLC bootstrap (original Host header kept).
        { "goshawk.capcom.co.jp", MH3U_GOSHAWK_HOST },

        // Lost Reavers (BNEI) - DNS-only, cos.xml stays on the original
        // hostname/HTTPS/443 (see lost_reavers_url.cpp).
        { "mars.project-treasure.bng.jp", LOST_REAVERS_HOST },

        // Just Dance 2016-2018 World Dance Floor (UbiServices + JMCS over HTTPS).
        { "jmcs-prod.just-dance.com", JD_WDF_HOST },
        { "api-ubiservices.ubi.com", JD_WDF_HOST },
        { "public-ubiservices.ubi.com", JD_WDF_HOST },

        // Need for Speed Most Wanted U: redirector (42127) answers with the game
        // server address; gosca (44125) is the CA-cert HTTP fetch.
        { "gosredirector.ea.com", NFS_BLAZE_HOST },
        { "gosca.ea.com", NFS_BLAZE_HOST },

        // Demae-Can Wii U channel replacement backend
        { "nws.demae-can.com", DEMAECAN_HOST },

        // BOSS (Background Online Storage Service) - SpotPass, tasksheets,
        // StreetPass relay, standby-mode notification delivery.
        { "npdi.cdn.nintendo.net", BOSS_NPDI_HOST },
        { "npdl.cdn.nintendo.net", BOSS_NPDL_HOST },
        { "npfl.c.app.nintendo.net", BOSS_NPFL_HOST },
        { "nppl.app.nintendo.net", BOSS_NPPL_HOST },
        { "nppl.c.app.nintendo.net", BOSS_NPPL_HOST },
        { "npts.app.nintendo.net", BOSS_NPTS_HOST },
        { "service.spr.app.nintendo.net", BOSS_SPR_HOST },

        // Call of Duty: Black Ops II (Wii U) - Demonware "ops2" backend.
        { "ops2-wiiu-cs.prod.demonware.net", BO2_OPS2_CS_HOST },
        { "ops2-wiiu-auth.prod.demonware.net", BO2_OPS2_AUTH_HOST },
        { "ops2-wiiu-lobby.prod.demonware.net", BO2_OPS2_LOBBY_HOST },
        { "ops2-wiiu-auth.demonware.net", BO2_OPS2_AUTH_HOST },
        { "ops2-wiiu-lobby.demonware.net", BO2_OPS2_LOBBY_HOST },
        { "ops2-wiiu-cs.demonware.net", BO2_OPS2_CS_HOST },
        { "ops2-wiiu-lsg.prod.demonware.net", BO2_OPS2_LOBBY_HOST },
        { "ops2-wiiu-lsg.demonware.net", BO2_OPS2_LOBBY_HOST },
        { "ops2-wiiu-stun.prod.demonware.net", BO2_OPS2_LOBBY_HOST },
        { "ops2-wiiu-stun.demonware.net", BO2_OPS2_LOBBY_HOST },
        { "cod7-stun.eu.demonware.net", BO2_OPS2_LOBBY_HOST },
        { "stun.eu.demonware.net", BO2_OPS2_LOBBY_HOST },
};

static const char * replace_dns_name(const char *dns_name) {
    if (!Config::connect_to_network || !dns_name) {
        return dns_name;
    }

    if (strstr(dns_name, "demonware.net") != nullptr) {
        // BO2's multiplayer RPL is loaded by the time it resolves Demonware, so
        // applying the auth-compatibility patch here avoids hooking the loader.
        patch_bo2_auth();
    }

    for (auto [original, replacement] : dns_replacements) {
        if (strcmp(original, dns_name) == 0) {
            DEBUG_FUNCTION_LINE_VERBOSE("Inkay/DNS: Redirecting %s -> %s", dns_name, replacement);
            return replacement;
        }
    }

    // Any other Demonware domain (regional/stun/umbrella...) falls back to the ops2 endpoints.
    if (strcasestr(dns_name, "demonware.net") != nullptr) {
        if (strcasestr(dns_name, "auth") != nullptr) return BO2_OPS2_AUTH_HOST;
        if (strcasestr(dns_name, "cs") != nullptr || strcasestr(dns_name, "content") != nullptr) return BO2_OPS2_CS_HOST;
        return BO2_OPS2_LOBBY_HOST;
    }

    // Just Dance: catch env-prefixed UbiServices hosts (PreProd...) and any other
    // JMCS subdomain. Broad - also grabs UbiServices for other Ubisoft Wii U
    // titles; narrow to a JD title check if that ever bites.
    if (strcasestr(dns_name, "ubiservices.ubi.com") != nullptr ||
        strcasestr(dns_name, "just-dance.com") != nullptr) {
        // The engine RPX is loaded by the time it resolves UbiServices; apply
        // the TLS cert-check bypass here (idempotent).
        patch_justdance_cert();
        return JD_WDF_HOST;
    }

    return dns_name;
}

DECL_FUNCTION(struct hostent *, gethostbyname, const char *dns_name) {
    return real_gethostbyname(replace_dns_name(dns_name));
}

DECL_FUNCTION(int, getaddrinfo, const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    return real_getaddrinfo(replace_dns_name(node), service, hints, res);
}

void patchDNS() {
    dns_patches.reserve(2);

    auto add_patch = [](function_replacement_data_t repl, const char *name) {
        PatchedFunctionHandle handle = 0;
        bool has_been_patched = false;
        FunctionPatcherStatus status = FunctionPatcher_AddFunctionPatch(&repl, &handle, &has_been_patched);
        if (status != FUNCTION_PATCHER_RESULT_SUCCESS) {
            DEBUG_FUNCTION_LINE("Inkay/DNS: Failed to patch %s!", name);
        }
        dns_patches.push_back(handle);
    };

    // FP_TARGET_PROCESS_GAME patches the launched game's process directly so
    // in-game DNS requests (e.g. Demonware, Karaoke U) are redirected accurately.
    add_patch(REPLACE_FUNCTION_FOR_PROCESS(gethostbyname, LIBRARY_NSYSNET, gethostbyname, FP_TARGET_PROCESS_GAME), "gethostbyname");
    add_patch(REPLACE_FUNCTION_FOR_PROCESS(getaddrinfo, LIBRARY_NSYSNET, getaddrinfo, FP_TARGET_PROCESS_GAME), "getaddrinfo");
}

void unpatchDNS() {
    for (auto handle: dns_patches) {
        FunctionPatcher_RemoveFunctionPatch(handle);
    }
    dns_patches.clear();
}
