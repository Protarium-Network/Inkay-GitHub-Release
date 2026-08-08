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

#include "config.h"
#include "utils/logger.h"
#include "inkay_config.h"
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
};

static const char * replace_dns_name(const char *dns_name) {
    if (!Config::connect_to_network || !dns_name) {
        return dns_name;
    }

    for (auto [original, replacement] : dns_replacements) {
        if (strcmp(original, dns_name) == 0) {
            DEBUG_FUNCTION_LINE_VERBOSE("Inkay/DNS: Redirecting %s -> %s", dns_name, replacement);
            return replacement;
        }
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
