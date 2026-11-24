// FIFA 13 Wii U online on the Protarium server (EA BlazeSDK 3.19.06, fifazf.rpx).
//
// The redirector connect (fn 0x030e1d28 -> 0x030dc738 host, port, secure) passes `secure` in r6 (`li r6, 1`);
// `li r6, 0` makes it plain TCP, and the main connection then follows the redirector's SECU field (the server sends 0).
// Same change as nfs_online.cpp. Only the RPX of the update (the code a console runs) was analysed; the site is
// verified word by word first and the patch is skipped as a whole on any other build.
#include "fifa_online.h"

#include <coreinit/title.h>
#include <string_view>

#include "Notification.h"
#include "config.h"
#include "utils/logger.h"
#include "utils/replace_mem.h"
#include "utils/rpl_info.h"

using namespace std::string_view_literals;

namespace {
// FIFA 13 EUR base = 0x1010ee00 (the only one seen); other regions are caught by the instruction check below.
constexpr uint32_t SECURE_SITE   = 0x030e1e24;
constexpr uint32_t SECURE_ORIG   = 0x38c00001; // li r6, 1
constexpr uint32_t SECURE_NEW    = 0x38c00000; // li r6, 0
constexpr uint32_t SECURE_BEFORE = 0x7fa9eb78; // mr r9, r29
constexpr uint32_t SECURE_AFTER  = 0x38e10018; // addi r7, r1, 24
constexpr uint32_t SECURE_CALL   = 0x4bffa909; // bl 0x030dc738 (2 words after the site)

} // namespace

void patch_fifa_online() {
    // no 'already applied' guard: the plugin outlives game launches, every launch has fresh (unpatched) memory
    if (OSGetTitleID() != 0x00050000'1010ee00ull) return; // ponytail: EUR only, add USA/JPN ids once seen on a console
    if (!Config::connect_to_network) {
        ShowNotification("FIFA 13: Protarium network is OFF in the plugin menu, patch skipped");
        return;
    }
    const auto rpx = search_for_rpl("fifazf.rpx"sv);
    if (!rpx) {
        DEBUG_FUNCTION_LINE("FIFA 13 patch skipped: fifazf.rpx not loaded");
        ShowNotification("FIFA 13: fifazf.rpx not found, patch skipped");
        return;
    }
    auto *site = static_cast<uint32_t *>(rpl_addr(*rpx, SECURE_SITE));
    if (site[-1] != SECURE_BEFORE || site[1] != SECURE_AFTER || site[3] != SECURE_CALL ||
        (*site != SECURE_ORIG && *site != SECURE_NEW)) {
        DEBUG_FUNCTION_LINE("FIFA 13: code differs from the analysed update (%08x %08x %08x), patch skipped", site[-1], *site, site[1]);
        ShowNotification("FIFA 13: game code differs from the analysed update, patch skipped");
        return;
    }
    if (*site != SECURE_NEW && !replace_instruction(site, SECURE_ORIG, SECURE_NEW)) {
        DEBUG_FUNCTION_LINE("FIFA 13: failed to patch the redirector secure flag");
        return;
    }
    DEBUG_FUNCTION_LINE("FIFA 13: plain-TCP redirector flag @%08x patched", (uint32_t) site);
    ShowNotification("FIFA 13: online plain TCP patch applied");
}
