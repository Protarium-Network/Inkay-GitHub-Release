// Minecraft: Wii U Edition, Minecraft.Client.rpx (update v688).
//
// Three sites guard the client-side integrity/anti-cheat validation path: three `bctrl` calls
// (virtual-call-style checks, two in one function and a third elsewhere) feeding a `bne` that only
// takes the "passed" branch when they all report success. On the Protarium server those checks have
// nothing real to validate against, so the path is forced to always succeed: all three `bctrl`s
// become `nop`, and the `bne` becomes an unconditional `b` to the exact same target (same
// displacement, just no longer conditional).
#include "mc_secure.h"

#include <coreinit/title.h>
#include <string_view>

#include "Notification.h"
#include "config.h"
#include "utils/logger.h"
#include "utils/replace_mem.h"
#include "utils/rpl_info.h"

using namespace std::string_view_literals;

#define MC_USA_TITLE_ID 0x00050000'101D9D00ull // USA
#define MC_EUR_TITLE_ID 0x00050000'101D7500ull // EUR

static const uint32_t ANTICHEAT_CALL_1      = 0x02703D84;
static const uint32_t ANTICHEAT_CALL_1_ORIG = 0x4E800421; // bctrl
static const uint32_t ANTICHEAT_CALL_2      = 0x02703DAC;
static const uint32_t ANTICHEAT_CALL_2_ORIG = 0x4E800421; // bctrl
static const uint32_t ANTICHEAT_CALL_3      = 0x0306F368;
static const uint32_t ANTICHEAT_CALL_3_ORIG = 0x4E800421; // bctrl
static const uint32_t ANTICHEAT_NOP         = 0x60000000; // nop

static const uint32_t ANTICHEAT_GATE      = 0x02703DB4;
static const uint32_t ANTICHEAT_GATE_ORIG = 0x40820090; // bne +0x90
static const uint32_t ANTICHEAT_GATE_NEW  = 0x48000090; // b   +0x90 (same target, unconditional)

static bool applied = false;

void patch_mc_secure() {
    if (applied) return; // once per game launch
    if (!Config::connect_to_network) return;

    const uint64_t title_id = OSGetTitleID();
    if (title_id != MC_USA_TITLE_ID && title_id != MC_EUR_TITLE_ID) return;

    auto rpx = search_for_rpl("Minecraft.Client.rpx"sv);
    if (!rpx) {
        DEBUG_FUNCTION_LINE("Minecraft Wii U: Minecraft.Client.rpx not found or not loaded");
        ShowNotification("Minecraft Wii U: Minecraft.Client.rpx not found or not loaded, patch skipped");
        return;
    }

    const auto version_opt = get_current_title_version();
    if (!version_opt || *version_opt != 688) {
        DEBUG_FUNCTION_LINE("Minecraft Wii U: wrong Minecraft version detected");
        return;
    }

    auto *call1 = static_cast<uint32_t *>(rpl_addr(*rpx, ANTICHEAT_CALL_1));
    auto *call2 = static_cast<uint32_t *>(rpl_addr(*rpx, ANTICHEAT_CALL_2));
    auto *call3 = static_cast<uint32_t *>(rpl_addr(*rpx, ANTICHEAT_CALL_3));
    auto *gate  = static_cast<uint32_t *>(rpl_addr(*rpx, ANTICHEAT_GATE));

    // All-or-nothing: every site must hold the v688 word (or our replacement, if already patched this boot).
    if ((*call1 != ANTICHEAT_CALL_1_ORIG && *call1 != ANTICHEAT_NOP) ||
        (*call2 != ANTICHEAT_CALL_2_ORIG && *call2 != ANTICHEAT_NOP) ||
        (*call3 != ANTICHEAT_CALL_3_ORIG && *call3 != ANTICHEAT_NOP) ||
        (*gate != ANTICHEAT_GATE_ORIG && *gate != ANTICHEAT_GATE_NEW)) {
        DEBUG_FUNCTION_LINE("Minecraft Wii U: title %016llx is not update v688 (words %08x %08x %08x %08x), patch skipped",
                            title_id, *call1, *call2, *call3, *gate);
        ShowNotification("Minecraft Wii U: game code differs from update v688, patch skipped");
        return;
    }

    if (*call1 != ANTICHEAT_NOP) replace_instruction(call1, ANTICHEAT_CALL_1_ORIG, ANTICHEAT_NOP);
    if (*call2 != ANTICHEAT_NOP) replace_instruction(call2, ANTICHEAT_CALL_2_ORIG, ANTICHEAT_NOP);
    if (*call3 != ANTICHEAT_NOP) replace_instruction(call3, ANTICHEAT_CALL_3_ORIG, ANTICHEAT_NOP);
    if (*gate != ANTICHEAT_GATE_NEW) replace_instruction(gate, ANTICHEAT_GATE_ORIG, ANTICHEAT_GATE_NEW);

    applied = true;
    DEBUG_FUNCTION_LINE("Minecraft Wii U: anti-cheat patch applied (@%08x %08x %08x %08x)", ANTICHEAT_CALL_1,
                        ANTICHEAT_CALL_2, ANTICHEAT_CALL_3, ANTICHEAT_GATE);
    ShowNotification("Minecraft Wii U: full online multiplayer + anti-cheat patch applied");
}