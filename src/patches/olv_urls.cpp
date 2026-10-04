/*  Copyright 2023 Pretendo Network contributors <pretendo.network>
    Copyright 2023 Ash Logan <ash@heyquark.com>
    Copyright 2019 Maschell

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

#include "config.h"
#include "olv_urls.h"
#include "utils/logger.h"
#include "utils/replace_mem.h"

#include <cstring>
#include <coreinit/dynload.h>
#include <coreinit/memory.h>

bool check_olv_libs() {
    OSDynLoad_Module olv_handle = 0;
    OSDynLoad_Error dret;

    dret = OSDynLoad_IsModuleLoaded("nn_olv", &olv_handle);
    if (dret == OS_DYNLOAD_OK && olv_handle != 0) {
        return true;
    }

    dret = OSDynLoad_IsModuleLoaded("nn_olv2", &olv_handle);
    if (dret == OS_DYNLOAD_OK && olv_handle != 0) {
        return true;
    }

    return false;
}

bool path_is_olv(const char* path) {
    if (!path) return false;

    const char *olv_names[] = {"nn_olv.rpl", "nn_olv2.rpl"};
    const auto path_len = strlen(path);
    for (const char *name: olv_names) {
        const auto suffix_len = strlen(name);
        if (path_len >= suffix_len && strcmp(path + path_len - suffix_len, name) == 0) {
            return true;
        }
    }
    return false;
}

static bool memory_contains(uint32_t start, uint32_t size, const char *value, size_t value_size) {
    if (!value || value_size == 0 || value_size > size) return false;
    for (uint32_t addr = start; addr <= start + size - value_size; addr++) {
        if (memcmp(value, reinterpret_cast<const void *>(addr), value_size) == 0) return true;
    }
    return false;
}

static bool notify_callback_registered = false;

void new_rpl_loaded(OSDynLoad_Module module, void* ctx, OSDynLoad_NotifyReason reason, OSDynLoad_NotifyData* rpl) {
    if (!Config::connect_to_network) {
        DEBUG_FUNCTION_LINE_VERBOSE("Inkay: Miiverse patches skipped.");
        return;
    }

    // Loaded olv?
    if (reason != OS_DYNLOAD_NOTIFY_LOADED) return;
    if (!rpl || !path_is_olv(rpl->name)) return;

    replace(rpl->dataAddr, rpl->dataSize, original_url, sizeof(original_url), new_url, sizeof(new_url));
}

bool setup_olv_libs() {
    if (!Config::connect_to_network) {
        DEBUG_FUNCTION_LINE_VERBOSE("Inkay: Miiverse patches skipped.");
        return false;
    }

    // setup_olv_libs is called both when an application starts and whenever
    // Miiverse opens. Registering the same callback repeatedly makes every
    // subsequent applet launch process the same RPL more than once.
    if (!notify_callback_registered) {
        OSDynLoad_AddNotifyCallback(&new_rpl_loaded, nullptr);
        notify_callback_registered = true;
    }

    auto olvLoaded = check_olv_libs();
    if (!olvLoaded) {
        DEBUG_FUNCTION_LINE_VERBOSE("Inkay: no olv, quitting for now\n");
        return false;
    }

    //wish there was a better way than "blow through MEM2"
    uint32_t base_addr, size;
    if (OSGetMemBound(OS_MEM2, &base_addr, &size)) {
        DEBUG_FUNCTION_LINE("Inkay: OSGetMemBound failed!");
        return false;
    }

    if (replace(base_addr, size, original_url, sizeof(original_url), new_url, sizeof(new_url))) return true;

    // On the second Miiverse opening the OLV module is often retained in MEM2
    // and already contains our endpoint. That is a valid state: the applet
    // allowlist still has to be patched again for the new browser instance.
    return memory_contains(base_addr, size, new_url, sizeof(new_url));
}
