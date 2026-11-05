#include "ghosts_auth.h"

#include <coreinit/memory.h>
#include <coreinit/memorymap.h>
#include <coreinit/title.h>
#include <cstring>
#include <cstdio>
#include <function_patcher/function_patching.h>
#include <string_view>

#include "config.h"
#include "Notification.h"
#include "sysconfig.h"
#include "utils/logger.h"
#include "utils/replace_mem.h"
#include "utils/rpl_info.h"

using namespace std::string_view_literals;

namespace {
// Only the USA build has been reverse-engineered so far (see cod-ghosts-wiiu/RE_REFERENCE.md):
// every address below comes from the USA iw6mp_cafef_rpl.rpl. The EUR and JPN title IDs are
// accepted too, but a regional build may be a different compile, so nothing is written unless
// EVERY patch site holds the instruction we expect (see patch_ghosts_auth); otherwise the patch
// is skipped as a whole and a single notification says so.
constexpr uint64_t GHOSTS_USA_TITLE_ID = 0x00050000'10146800; // WUP-P-ACPE
constexpr uint64_t GHOSTS_EUR_TITLE_ID = 0x00050000'10156100; // WUP-P-ACPP (English, French, German)
constexpr uint64_t GHOSTS_EUR_ESIT_TITLE_ID = 0x00050000'10157600; // WUP-P-ACPI (Spanish, Italian)
constexpr uint64_t GHOSTS_JPN_TITLE_ID = 0x00050000'10157900; // WUP-P-ACPJ

// iw6mp_cafef_rpl.rpl, USA. All addresses found via the RPL's own (non-stripped) ELF symbol
// table + capstone disassembly, not blind RE -- see cod-ghosts-wiiu/RE_REFERENCE.md for the walk.

// 1) RSA signature verification gate. bdRSAKey::verifyHash() can never succeed for a
// console-signed ticket (no private key), same root cause as BO2's RSA_VERIFY_BRANCH patch.
// Two call sites both check `cmpwi r3,0 ; bne <fail>` right after the call and both need the
// `bne` turned into an unconditional `b` to the same target.
constexpr uint32_t RSA_GATE_1 = 0x029138a0; // bdAuthService::handleWiiUReplies
constexpr uint32_t RSA_GATE_1_BNE = 0x40820070; // bne 0x2913910
constexpr uint32_t RSA_GATE_1_BYPASS = 0x48000070; // b   0x2913910

constexpr uint32_t RSA_GATE_2 = 0x029370d8; // bdAuthService::handleReply (generic path)
constexpr uint32_t RSA_GATE_2_BNE = 0x408200f4; // bne 0x29371cc
constexpr uint32_t RSA_GATE_2_BYPASS = 0x480000f4; // b   0x29371cc

// 2) Ticket-magic check, right after the RSA gate in the same function
// (bdAuthService::handleWiiUReplies). After deserializing the auth ticket
// (bdAuthTicket::deserialize @ 0x02918b94), the client compares a field at
// offset 0xc8 of its own auth-service object against a fixed expected magic
// constant; on mismatch it sets an internal error code (0x2cc) and the whole
// login is treated as failed, causing the client to loop back and retry the
// entire WiiUForMmpRequest2 handshake from scratch (observed live: repeating
// ~60s cycles, auth handshake succeeds server-side every time but the client
// never proceeds past it). dw-server has no way to know/produce this expected
// magic value, so -- same root cause and same fix as BO2's ticket-magic NOP --
// turn the `bne` into a NOP so the comparison result is ignored entirely.
constexpr uint32_t TICKET_MAGIC_GATE = 0x02913958; // bdAuthService::handleWiiUReplies
constexpr uint32_t TICKET_MAGIC_BNE = 0x40820068; // bne 0x29139c0
constexpr uint32_t TICKET_MAGIC_NOP = 0x60000000; // nop

// 3) bdCommonAddr::getNATType() -- a 2-instruction getter (`lwz r3,0x9c(r3) ; blr`) read by
// bdNATTravClient::connectionAllowed(), whose logic is byte-for-byte identical to BO2's
// (natA==Open || natB==Open || (natA==Moderate && natB==Moderate)). Same fix as BO2's nat-open
// stub: force it to always report Open (1), which unblocks connectionAllowed() for free.
constexpr uint32_t NAT_TYPE_FUNC = 0x028dc18c;
constexpr uint32_t NAT_TYPE_ORIGINAL = 0x8063009c; // lwz r3, 0x9c(r3)
constexpr uint32_t NAT_TYPE_RETURN_OPEN = 0x38600001; // li r3, 1

// 4) Live_Base_IsUserNetworkConnectionAllowed() -- Ghosts' equivalent of BO2's
// Live_HasMultiplayerPrivileges: reads a per-client byte (parental-control flag) that nothing
// on a real Nintendo Network account ever sets. Stub the whole function to `li r3,1 ; blr`.
constexpr uint32_t MP_PRIVILEGES_FUNC = 0x02703870;
constexpr uint32_t MP_PRIVILEGES_ORIGINAL_0 = 0x7c0802a6; // mflr r0
constexpr uint32_t MP_PRIVILEGES_ORIGINAL_1 = 0x9421ffe8; // stwu r1, -0x18(r1)
constexpr uint32_t MP_PRIVILEGES_RETURN_TRUE_0 = 0x38600001; // li r3, 1
constexpr uint32_t MP_PRIVILEGES_RETURN_TRUE_1 = 0x4e800020; // blr

// 5) News + image-of-the-day gates. Live_SyncOnlineDataFlags (the "retrieving online profile" popup)
// stays blocked on LiveStorage_DoWeHaveNews (0x8000) and LiveStorage_DoWeHaveIOTD (0x4000); nothing
// ever fetches either on our server (diagnostic flags read 0xE000), and both are cosmetic. Stub both
// to `li r3,1 ; blr` (first two instructions, original bytes read from the USA RPL).
constexpr uint32_t HAVE_NEWS_FUNC = 0x02565a98;
constexpr uint32_t HAVE_NEWS_ORIGINAL_0 = 0x3d8011e4; // lis r12, 0x11e4
constexpr uint32_t HAVE_NEWS_ORIGINAL_1 = 0x818c8304; // lwz r12, -0x7cfc(r12)
constexpr uint32_t HAVE_IOTD_FUNC = 0x02562a70;
constexpr uint32_t HAVE_IOTD_ORIGINAL_0 = 0x3d8011e4; // lis r12, 0x11e4
constexpr uint32_t HAVE_IOTD_ORIGINAL_1 = 0x818c8254; // lwz r12, -0x7dac(r12)
constexpr uint32_t RETURN_TRUE_0 = 0x38600001; // li r3, 1
constexpr uint32_t RETURN_TRUE_1 = 0x4e800020; // blr

// Tried (2026-09-17): stubbing LiveStorage_DoWeHavePlaylists() (0x0257486c, lbz->li r3,1) to
// skip the playlists_tu4.aggr fetch loop entirely. Address/original bytes were re-verified byte
// for byte against the RPL and matched, but the patch still reported "address mismatch" live on
// console every retry cycle. Couldn't get a UDP debug log from the console to see the actual
// instruction value it read (WHBLogUdp packets never reached a listener on the PC, even over the
// same LAN -- not investigated further). Reverted rather than ship a patch that visibly spams a
// bogus notification without a confirmed working effect. If revisited, get real debug log output
// first before re-attempting -- see cod-ghosts-wiiu/RE_REFERENCE.md.

}

#ifdef GHOSTS_DIAG
// Diagnostic, polled from the game's own frame loop; every change is shown as a notification.
//  - Live_SyncOnlineDataFlags: bitmask of what the "retrieving online profile" popup waits on.
//  - Public search: how many results PartyHost_SearchComplete handed to the party code
//    (PartyData+0x2534), whether QoS probes are running (Live_QoSInProgress), how many probes
//    dwStartQoSProbes started (listener+0x5b0) and how many answered (listener+0x27b0).
//    "found=0" means the client dropped every row before QoS; "found=N started=0" means all were
//    skipped; "started=N done=0" means the hosts did not answer the probe.
static OSDynLoad_NotifyData g_diag_rpl;
static void *g_sync_flags_fn = nullptr;
constexpr uint32_t SYNC_FLAGS_FUNC = 0x027ec040;
constexpr uint32_t GET_PARTY_DATA_FUNC = 0x023254fc;  // Lobby_GetPartyData
constexpr uint32_t QOS_IN_PROGRESS_FUNC = 0x027066f0; // Live_QoSInProgress
constexpr uint32_t QOS_LISTENER = 0x11a252b8;         // dwQoSMultiProbeListener, first slot

static bool diag_readable(const void *p) { return OSIsAddressValid(reinterpret_cast<uint32_t>(p)); }

static void diag_search_state() {
    static char last[64] = "";
    const auto party = reinterpret_cast<uint8_t *(*)()>(rpl_addr(g_diag_rpl, GET_PARTY_DATA_FUNC))();
    const int in_progress = reinterpret_cast<int (*)()>(rpl_addr(g_diag_rpl, QOS_IN_PROGRESS_FUNC))();
    const auto listener = static_cast<uint8_t *>(rpl_addr(g_diag_rpl, QOS_LISTENER));

    int found = -1;
    if (party && diag_readable(party + 0x2534)) found = *reinterpret_cast<int *>(party + 0x2534);
    uint32_t started = 0xFFFF, done = 0xFFFF;
    if (diag_readable(listener + 0x5b0) && diag_readable(listener + 0x27b0)) {
        started = *reinterpret_cast<uint32_t *>(listener + 0x5b0);
        done = *reinterpret_cast<uint32_t *>(listener + 0x27b0);
    }
    char now[64];
    snprintf(now, sizeof(now), "Ghosts MM: found=%d qos=%d started=%u done=%u", found, in_progress, started, done);
    if (strcmp(now, last) != 0) {
        strcpy(last, now);
        DEBUG_FUNCTION_LINE("%s", now);
        ShowNotification(now);
    }
}

DECL_FUNCTION(void, GX2SwapScanBuffers_ghostsdiag) {
    static uint32_t frames = 0;
    static uint32_t last = 0xFFFFFFFF;
    real_GX2SwapScanBuffers_ghostsdiag();
    if (g_sync_flags_fn && ++frames % 120 == 0) {
        const uint32_t flags = reinterpret_cast<uint32_t (*)(int)>(g_sync_flags_fn)(0);
        if (flags != last) {
            last = flags;
            char msg[48];
            snprintf(msg, sizeof(msg), "Ghosts sync flags: 0x%X", flags);
            DEBUG_FUNCTION_LINE("%s", msg);
            ShowNotification(msg);
        }
        diag_search_state();
    }
}

static void install_sync_flags_diag(OSDynLoad_NotifyData rpl) {
    static bool installed = false;
    if (installed) return;
    installed = true;
    g_diag_rpl = rpl;
    g_sync_flags_fn = rpl_addr(rpl, SYNC_FLAGS_FUNC);
    function_replacement_data_t repl = REPLACE_FUNCTION_FOR_PROCESS(
        GX2SwapScanBuffers_ghostsdiag, LIBRARY_GX2, GX2SwapScanBuffers, FP_TARGET_PROCESS_GAME);
    PatchedFunctionHandle handle = 0;
    if (FunctionPatcher_AddFunctionPatch(&repl, &handle, nullptr) != FUNCTION_PATCHER_RESULT_SUCCESS) {
        DEBUG_FUNCTION_LINE("Ghosts sync-flags diagnostic: failed to hook GX2SwapScanBuffers");
        g_sync_flags_fn = nullptr;
    }
}
#endif // GHOSTS_DIAG

namespace {
struct Site {
    uint32_t addr;
    uint32_t original;
    uint32_t replacement;
    bool hi16_only; // lis/lwz that references .data: the loader rewrites the low 16 bits
    const char *name;
};

const Site SITES[] = {
    {RSA_GATE_1, RSA_GATE_1_BNE, RSA_GATE_1_BYPASS, false, "RSA gate 1"},
    {RSA_GATE_2, RSA_GATE_2_BNE, RSA_GATE_2_BYPASS, false, "RSA gate 2"},
    {TICKET_MAGIC_GATE, TICKET_MAGIC_BNE, TICKET_MAGIC_NOP, false, "ticket-magic"},
    {NAT_TYPE_FUNC, NAT_TYPE_ORIGINAL, NAT_TYPE_RETURN_OPEN, false, "nat-open"},
    {MP_PRIVILEGES_FUNC, MP_PRIVILEGES_ORIGINAL_0, MP_PRIVILEGES_RETURN_TRUE_0, false, "mp-privileges (0)"},
    {MP_PRIVILEGES_FUNC + 4, MP_PRIVILEGES_ORIGINAL_1, MP_PRIVILEGES_RETURN_TRUE_1, false, "mp-privileges (1)"},
    {HAVE_NEWS_FUNC, HAVE_NEWS_ORIGINAL_0, RETURN_TRUE_0, true, "have-news (0)"},
    {HAVE_NEWS_FUNC + 4, HAVE_NEWS_ORIGINAL_1, RETURN_TRUE_1, true, "have-news (1)"},
    {HAVE_IOTD_FUNC, HAVE_IOTD_ORIGINAL_0, RETURN_TRUE_0, true, "have-iotd (0)"},
    {HAVE_IOTD_FUNC + 4, HAVE_IOTD_ORIGINAL_1, RETURN_TRUE_1, true, "have-iotd (1)"},
};

bool site_ready(OSDynLoad_NotifyData rpl, const Site &site) {
    const uint32_t cur = *static_cast<uint32_t *>(rpl_addr(rpl, site.addr));
    if (cur == site.replacement) return true; // already applied
    const uint32_t mask = site.hi16_only ? 0xFFFF0000 : 0xFFFFFFFF;
    if ((cur & mask) == (site.original & mask)) return true;
    DEBUG_FUNCTION_LINE("Ghosts auth patch not applicable (%s @ %08x): found %08x", site.name, site.addr, cur);
    return false;
}

enum class PatchState { Pending, Applied, Unsupported };
PatchState g_state = PatchState::Pending;
}

void patch_ghosts_auth() {
    if (!Config::connect_to_network) return;
    if (g_state != PatchState::Pending) return; // applied (or refused) once per game launch

    const uint64_t title_id = OSGetTitleID();
    if (title_id != GHOSTS_USA_TITLE_ID && title_id != GHOSTS_EUR_TITLE_ID &&
        title_id != GHOSTS_EUR_ESIT_TITLE_ID && title_id != GHOSTS_JPN_TITLE_ID) return;

    const auto multiplayer = search_for_rpl("iw6mp_cafef_rpl.rpl"sv);
    if (!multiplayer) {
        DEBUG_FUNCTION_LINE("Ghosts auth patch skipped: multiplayer RPL not loaded");
        return;
    }

    // All-or-nothing: a regional build that differs from the USA one must not be half patched.
    bool all_match = true;
    for (const Site &site : SITES) all_match &= site_ready(*multiplayer, site);
    if (!all_match) {
        g_state = PatchState::Unsupported;
        DEBUG_FUNCTION_LINE("Ghosts: title %016llx is not the build the patch addresses come from", title_id);
        return;
    }

    for (const Site &site : SITES) {
        auto *inst = static_cast<uint32_t *>(rpl_addr(*multiplayer, site.addr));
        if (*inst != site.replacement) replace_instruction(inst, *inst, site.replacement);
    }
    g_state = PatchState::Applied;

#ifdef GHOSTS_DIAG
    install_sync_flags_diag(*multiplayer);
#endif

    DEBUG_FUNCTION_LINE("Ghosts auth compatibility patches applied");
    ShowNotification("CoD Ghosts: authentication compatibility patch applied");
}