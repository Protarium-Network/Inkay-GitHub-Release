// Need for Speed Most Wanted U online on the Protarium server (Blaze, EA BlazeSDK 3.19).
//
// The game's Blaze login job asks FUN 0x02c1eb3c ("is this user logged in?"): hub connected AND login state 11 AND a
// per-user flag (first byte of a login-token string in the network manager) that the real EA servers' login flow
// set and our login never does. With state 11 but the flag clear, the login state machine neither answers nor
// starts a login, and the game waits on the loading screen, then shows "Erreur de connexion" (Origin powered by EA).
//
// The first fix is one instruction: the function ends with `xori r0, r0, 1 ; clrlwi r3, r0, 24` (result = flag != 0).
// Replacing the `clrlwi` with `li r3, 1` makes it return "logged in" whenever hub and state are fine.
// Only update v32 (the code a console runs: base v0 + update v32) is known; every word is verified first and the
// patch is skipped as a whole on any other build.
//
// Second patch, plain TCP: the community server (a Python Blaze server, no SSL stack) speaks unencrypted Blaze. The
// redirector connect (0x030f11b8 -> 0x030eb9bc host, port, secure) passes `secure` in r6 (`li r6, 1`); `li r6, 0`
// makes it plain TCP, and the main connection then follows the redirector's SECU field (the server sends 0).
//
// Credit: found independently by the "NFSMWU Online Community" project (AGPL-3.0), which patches the same
// function from its own Aroma plugin; this is a minimal re-implementation of just that one change.
#include "nfs_online.h"

#include <coreinit/title.h>
#include <string_view>

#include "Notification.h"
#include "config.h"
#include "utils/logger.h"
#include "utils/replace_mem.h"
#include "utils/rpl_info.h"

using namespace std::string_view_literals;

namespace {
// USA / EUR / JPN title IDs and the user's install are matched by the instruction check below; this list only keeps
// the lookup quiet in other titles. (EUR = 0x10128400 is the one tested.)
constexpr uint64_t NFS_TITLE_IDS[] = {0x00050000'10128400ull, 0x00050000'10128800ull, 0x00050000'10128900ull,
                                      0x00050000'1012BC00ull};

constexpr uint32_t FN_IS_LOGGED_IN = 0x02c1eb3c; // Hawaii.rpx v32: IsLoggedInToServer
constexpr uint32_t FN_PROLOGUE[2]  = {0x7c0802a6, 0x9421fff0};   // mflr r0 ; stwu r1, -16(r1)
constexpr uint32_t SITE            = 0x02c1eb9c;                // clrlwi r3, r0, 24
constexpr uint32_t SITE_ORIG       = 0x5403063e;
constexpr uint32_t SITE_NEW        = 0x38600001;                // li r3, 1
constexpr uint32_t SITE_BEFORE[2]  = {0x5540d97e, 0x68000001};  // rlwinm r0, r10, 27, 5, 31 ; xori r0, r0, 1

constexpr uint32_t SECURE_SITE     = 0x030f1308;
constexpr uint32_t SECURE_ORIG     = 0x38c00001;                // li r6, 1
constexpr uint32_t SECURE_NEW      = 0x38c00000;                // li r6, 0
constexpr uint32_t SECURE_BEFORE   = 0x38e10018;                // addi r7, r1, 24
constexpr uint32_t SECURE_AFTER    = 0x7fc5f378;                // mr r5, r30

bool applied = false;
} // namespace

void patch_nfs_online() {
    if (applied) return; // once per game launch

    const uint64_t title_id = OSGetTitleID();
    bool known = false;
    for (const uint64_t id : NFS_TITLE_IDS) known |= (title_id == id);
    if (!known) return;
    // Diagnostic toasts (NFS only): tell the user exactly why nothing was patched.
    if (!Config::connect_to_network) {
        ShowNotification("NFS MW U: Protarium network is OFF in the plugin menu, patch skipped");
        return;
    }

    // the loader lists the RPX by its internal name (Hawaii_CAFE_External_Unity.rpx), not the file name on disk
    auto rpx = search_for_rpl("Hawaii_CAFE_External_Unity.rpx"sv);
    if (!rpx) rpx = search_for_rpl("Hawaii.rpx"sv);
    if (!rpx) {
        DEBUG_FUNCTION_LINE("NFS MW U patch skipped: Hawaii.rpx not loaded");
        ShowNotification("NFS MW U: Hawaii.rpx not found, patch skipped");
        return;
    }

    const auto *fn   = static_cast<const uint32_t *>(rpl_addr(*rpx, FN_IS_LOGGED_IN));
    auto *site       = static_cast<uint32_t *>(rpl_addr(*rpx, SITE));
    const auto *prev = site - 2;
    auto *secure     = static_cast<uint32_t *>(rpl_addr(*rpx, SECURE_SITE));
    // All-or-nothing: both sites must hold the v32 words (or our replacement, if already patched this boot).
    if (fn[0] != FN_PROLOGUE[0] || fn[1] != FN_PROLOGUE[1] || prev[0] != SITE_BEFORE[0] || prev[1] != SITE_BEFORE[1] ||
        (*site != SITE_ORIG && *site != SITE_NEW) || secure[-1] != SECURE_BEFORE || secure[1] != SECURE_AFTER ||
        (*secure != SECURE_ORIG && *secure != SECURE_NEW)) {
        DEBUG_FUNCTION_LINE("NFS MW U: title %016llx is not update v32 (words %08x %08x %08x %08x), patch skipped", title_id,
                            fn[0], fn[1], *site, *secure);
        ShowNotification("NFS MW U: game code differs from update v32, patch skipped");
        return;
    }

    if (*site != SITE_NEW && !replace_instruction(site, SITE_ORIG, SITE_NEW)) {
        DEBUG_FUNCTION_LINE("NFS MW U: failed to patch the logged-in check");
        return;
    }
    if (*secure != SECURE_NEW && !replace_instruction(secure, SECURE_ORIG, SECURE_NEW)) {
        DEBUG_FUNCTION_LINE("NFS MW U: failed to patch the redirector secure flag");
        return;
    }
    applied = true;
    DEBUG_FUNCTION_LINE("NFS MW U: logged-in check @%08x and plain-TCP flag @%08x patched", (uint32_t) site, (uint32_t) secure);
    ShowNotification("NFS Most Wanted U: online login + plain TCP patch applied");
}
