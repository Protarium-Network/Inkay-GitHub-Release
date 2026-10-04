/*  Copyright 2026 Pretendo Network contributors <pretendo.network>

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

// Lost Reavers (BNEI) links its own libcurl directly into its RPX
// (.fimport_nlibcurl, confirmed via RPX disassembly) and does its own TLS
// certificate validation through it - unlike most other Nintendo Network
// traffic, which goes through IOSU's nn_ssl and is already covered by
// Inkay's own IOSU-level SSL-verification bypass (see main.cpp's
// Mocha_IOSUKernelWrite32 calls). That bypass never reaches this game's own
// curl, so a DNS-only redirect to a self-signed certificate (the approach
// dns_hooks.cpp otherwise uses for every other retired-server redirect)
// fails here: curl's own cert check rejects the connection outright, with
// no visible error - the game just stops connecting the moment its cos.xml
// argstr points back at the real (now-dead) HTTPS host.
//
// Rewriting the URL string itself, in this hook, sidesteps the problem
// entirely: the game's curl never attempts a TLS handshake with anyone,
// because the URL it ends up actually using is plain HTTP, against a host
// this project's own Caddy already reverse-proxies to the Lost Reavers
// stub (the same plain-HTTP base URL that was wired up when
// this game's cos.xml was still being edited directly - this hook removes
// the need for that NAND-side edit instead of replacing it with a
// DNS+certificate workaround that this game's own curl can't accept).
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include <function_patcher/function_patching.h>

#include "config.h"
#include "inkay_config.h"
#include "utils/logger.h"

namespace {
constexpr int CURLOPT_URL = 10002;

constexpr char ORIGINAL_HOST[]     = "mars.project-treasure.bng.jp";
constexpr char REPLACEMENT_BASE[]  = LOST_REAVERS_BASE_URL;

// libcurl copies CURLOPT_URL's string internally as soon as the setopt call
// returns, so one static buffer reused across calls is safe - it only has
// to stay valid for the duration of this single call.
char sRewrittenUrl[512];

const char *rewrite_lost_reavers_url(const char *url) {
    if (!url) {
        return nullptr;
    }
    const char *hostStart = std::strstr(url, ORIGINAL_HOST);
    if (!hostStart) {
        return nullptr;
    }
    const char *afterHost = hostStart + (sizeof(ORIGINAL_HOST) - 1);
    // Skip an explicit ":port" if the game ever includes one after the host.
    if (*afterHost == ':') {
        afterHost++;
        while (*afterHost >= '0' && *afterHost <= '9') {
            afterHost++;
        }
    }
    std::snprintf(sRewrittenUrl, sizeof(sRewrittenUrl), "%s%s", REPLACEMENT_BASE, afterHost);
    return sRewrittenUrl;
}
} // namespace

std::vector<PatchedFunctionHandle> lost_reavers_url_patches;

DECL_FUNCTION(int, lr_curl_easy_setopt, void *handle, int option, uint32_t value) {
    if (option == CURLOPT_URL) {
        const char *rewritten = rewrite_lost_reavers_url((const char *) value);
        if (rewritten) {
            DEBUG_FUNCTION_LINE_VERBOSE("Inkay/LostReavers: rewriting URL to %s", rewritten);
            return real_lr_curl_easy_setopt(handle, option, (uint32_t) rewritten);
        }
    }
    return real_lr_curl_easy_setopt(handle, option, value);
}

void patch_lost_reavers_url() {
    if (!Config::connect_to_network) {
        return;
    }

    lost_reavers_url_patches.reserve(1);

    function_replacement_data_t repl = REPLACE_FUNCTION(lr_curl_easy_setopt, LIBRARY_NLIBCURL, curl_easy_setopt);
    PatchedFunctionHandle handle      = 0;
    if (FunctionPatcher_AddFunctionPatch(&repl, &handle, nullptr) != FUNCTION_PATCHER_RESULT_SUCCESS) {
        DEBUG_FUNCTION_LINE("Inkay/LostReavers: Failed to patch curl_easy_setopt!");
    }
    lost_reavers_url_patches.push_back(handle);
}

void unpatch_lost_reavers_url() {
    for (auto h : lost_reavers_url_patches) {
        FunctionPatcher_RemoveFunctionPatch(h);
    }
    lost_reavers_url_patches.clear();
}
