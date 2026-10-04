/*  Copyright 2024 Pretendo Network contributors <pretendo.network>
    Copyright 2024 Ash Logan <ash@heyquark.com>

    Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby
    granted, provided that the above copyright notice and this permission notice appear in all copies.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
    INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
    IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
    PERFORMANCE OF THIS SOFTWARE.
*/

#include <coreinit/title.h>
#include <coreinit/dynload.h>
#include "game_peertopeer.h"

#include "config.h"
#include "Notification.h"
#include "sysconfig.h"
#include "utils/logger.h"
#include "utils/rpl_info.h"
#include "utils/replace_mem.h"

#include <optional>
#include <algorithm>
#include <string_view>
using namespace std::string_view_literals;

static struct {
    std::array<uint64_t, 3> tid;
    uint16_t version;
    uint32_t min_port_addr;
    uint32_t max_port_addr;
    std::string_view rpx;
} generic_patch_games[] = {
    {
        // MARIO KART 8
        {0x00050000'1010ec00, 0x00050000'1010ed00, 0x00050000'1010eb00},
        81,
        0x101a9a52,
        0x101a9a54,
        "Turbo.rpx"sv,
    },
    {
        // Splatoon
        {0x00050000'10176900, 0x00050000'10176a00, 0x00050000'10162b00},
        288,
        0x101e8952,
        0x101e8954,
        "Gambit.rpx"sv,
    },
};

static void generic_peertopeer_patch() {
    uint64_t tid = OSGetTitleID();
    uint16_t title_version = 0;
    if (const auto version_opt = get_current_title_version(); !version_opt) {
        DEBUG_FUNCTION_LINE("Failed to detect current title version");
        return;
    } else {
        title_version = *version_opt;
        DEBUG_FUNCTION_LINE("Title version detected: %d", title_version);
    }

    for (const auto &patch: generic_patch_games) {
        if (std::ranges::find(patch.tid, tid) == patch.tid.end()) continue;

        std::optional<OSDynLoad_NotifyData> game = search_for_rpl(patch.rpx);
        if (!game) {
            DEBUG_FUNCTION_LINE("Couldn't find game rpx! (%s)", patch.rpx.data());
            return;
        }

        if (title_version != patch.version) {
            DEBUG_FUNCTION_LINE("Unexpected title version. Expected %d but got %d (%s)", patch.version, title_version,
                                patch.rpx.data());
            continue;
        }

        auto port = get_console_peertopeer_port();
        DEBUG_FUNCTION_LINE_VERBOSE("Will use port %d. %08x", port, game->textAddr);

        auto target = (uint16_t *)rpl_addr(*game, patch.min_port_addr);
        replace_unsigned<uint16_t>(target, 0xc000, port);

        target = (uint16_t *)rpl_addr(*game, patch.max_port_addr);
        replace_unsigned<uint16_t>(target, 0xffff, port);
        break;
    }
}

static void minecraft_peertopeer_patch() {
    std::optional<OSDynLoad_NotifyData> minecraft = search_for_rpl("Minecraft.Client.rpx"sv);
    if (!minecraft) {
        DEBUG_FUNCTION_LINE("Couldn't find minecraft rpx!");
        return;
    }
    if (const auto version_opt = get_current_title_version(); !version_opt || *version_opt != 688) {
        DEBUG_FUNCTION_LINE("Wrong mincecraft version detected");
        return;
    }

    auto port = get_console_peertopeer_port();
    DEBUG_FUNCTION_LINE_VERBOSE("Will use port %d. %08x", port, minecraft->textAddr);

    auto target_func = (uint32_t *)rpl_addr(*minecraft, 0x03579530);
    replace_instruction(&target_func[0], 0x3c600001, 0x3c600000);        // li r3, 0
    replace_instruction(&target_func[1], 0x3863c000, 0x60630000 | port); // ori r3, r3, port
    // blr

    target_func = (uint32_t *)rpl_addr(*minecraft, 0x0357953c);
    replace_instruction(&target_func[0], 0x3c600001, 0x3c600000);        // li r3, 0
    replace_instruction(&target_func[1], 0x3863ffff, 0x60630000 | port); // ori r3, r3, port
    // blr
}

static void sonic_transformed_peertopeer_patch() {
    // Sonic & All-Stars Racing Transformed update RPX (SART.rpx), SHA-256:
    // 9B74170C82296223B10581A7C336AF7B9BB904C5C08E8567C3A48CA3C040C957
    //
    // NEX uses both RootTransport::GetWellKnownPortNumber() and
    // RootTransport::GetNextPortNumber() while preparing NAT traversal. The
    // latter normally selects a random port in 0xc000..0xffff, which makes the
    // station URL disagree with the stable port forwarded by Inkay.
    constexpr uint32_t get_well_known_port = 0x02de4598;
    constexpr uint32_t get_next_port = 0x02de4b5c;

    std::optional<OSDynLoad_NotifyData> sonic = search_for_rpl("SART.rpx"sv);
    if (!sonic) {
        DEBUG_FUNCTION_LINE("Couldn't find Sonic Transformed rpx!");
        return;
    }

    auto *well_known = (uint32_t *) rpl_addr(*sonic, get_well_known_port);
    auto *next = (uint32_t *) rpl_addr(*sonic, get_next_port);

    constexpr std::array<uint32_t, 3> well_known_original = {
        0x3c601032, // lis r3, 0x1032
        0x386319d8, // addi r3, r3, 0x19d8
        0x4bfba934, // b RootTransport well-known-port storage getter
    };
    constexpr std::array<uint32_t, 3> next_original = {
        0x7c0802a6, // mflr r0
        0x90010004, // stw r0, 4(r1)
        0x38603fff, // li r3, 0x3fff (random range size)
    };

    if (!std::equal(well_known_original.begin(), well_known_original.end(), well_known) ||
        !std::equal(next_original.begin(), next_original.end(), next)) {
        DEBUG_FUNCTION_LINE("Sonic Transformed P2P patch skipped: unexpected instructions");
        ShowNotification("Sonic Racing: P2P patch address mismatch");
        return;
    }

    const uint16_t port = get_console_peertopeer_port();
    const std::array<uint32_t, 3> fixed_port_return = {
        0x3c600000,             // lis r3, 0
        0x60630000 | static_cast<uint32_t>(port), // ori r3, r3, port
        0x4e800020,             // blr
    };

    bool applied = true;
    for (size_t i = 0; i < fixed_port_return.size(); i++) {
        applied &= replace_instruction(&well_known[i], well_known_original[i], fixed_port_return[i]);
        applied &= replace_instruction(&next[i], next_original[i], fixed_port_return[i]);
    }

    if (applied) {
        DEBUG_FUNCTION_LINE("Sonic Transformed fixed P2P port patch applied: %u", port);
        ShowNotification("Sonic Racing: fixed P2P port patch applied");
    } else {
        DEBUG_FUNCTION_LINE("Sonic Transformed P2P patch failed while writing instructions");
        ShowNotification("Sonic Racing: P2P patch failed");
    }
}

void peertopeer_patch() {
    if (!Config::connect_to_network) {
        return;
    }

    uint64_t tid = OSGetTitleID();
    if (tid == 0x00050000'1010B300 || // Sonic Transformed USA
        tid == 0x00050000'10111F00 || // Sonic Transformed EUR
        tid == 0x00050000'1015B400) { // Sonic Transformed JPN

        sonic_transformed_peertopeer_patch();
    } else if (tid == 0x00050000'101D7500 || // EUR
        tid == 0x00050000'101D9D00 || // USA
        tid == 0x00050000'101DBE00) { // JPN

        minecraft_peertopeer_patch();
    } else {
        generic_peertopeer_patch();
    }
}
