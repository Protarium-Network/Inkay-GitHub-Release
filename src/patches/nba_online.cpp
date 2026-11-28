#include "nba_online.h"

#include <coreinit/title.h>
#include <string_view>

#include "Notification.h"
#include "config.h"
#include "utils/logger.h"
#include "utils/replace_mem.h"
#include "utils/rpl_info.h"

using namespace std::string_view_literals;

const uint64_t NBA2K13_TITLE_IDS[] = {0x00050000'10112F00ull, 0x00050000'1010DA00ull};

// TODO - Check whether these addresses also exist for the USA version,
// if they are offset, search for the correct ones. Also, I need to test this NBA2K13 patch at some point
static const uint32_t SECURE_SITE   = 0x024d4f78;
static const uint32_t SECURE_ORIG   = 0x38c00001; // li r6, 1
static const uint32_t SECURE_NEW    = 0x38c00000; // li r6, 0
static const uint32_t SECURE_BEFORE = 0x38e10018; // addi r7, r1, 24
static const uint32_t SECURE_AFTER  = 0xd1a10010; // stfs f13, 16(r1)
static const uint32_t SECURE_CALL   = 0x4bb396e1; // bl 0x0200e668 (4 words after the site)

void patch_nba_online() {
    const uint64_t title_id = OSGetTitleID();
    bool known = false;
    for (const uint64_t id : NBA2K13_TITLE_IDS) known |= (id != 0 && title_id == id);
    if (!known) return;

    if (!Config::connect_to_network) return;

    // the loader lists the RPX by its internal name, not the file name on disk
    const auto rpx = search_for_rpl("nba_clean_opt.rpx"sv);
    if (!rpx) {
        DEBUG_FUNCTION_LINE("NBA 2K13 patch skipped: nba_clean_opt.rpx not found or not loaded");
        ShowNotification("NBA 2K13: nba_clean_opt.rpx not found or not loaded, patch skipped");
        return;
    }
    auto *site = static_cast<uint32_t *>(rpl_addr(*rpx, SECURE_SITE));
    if (site[-1] != SECURE_BEFORE || site[1] != SECURE_AFTER || site[4] != SECURE_CALL ||
        (*site != SECURE_ORIG && *site != SECURE_NEW)) {
        DEBUG_FUNCTION_LINE("NBA 2K13: code differs from the analysed update (%08x %08x %08x), patch skipped", site[-1], *site, site[1]);
        ShowNotification("NBA 2K13: game code differs from the analysed update, patch skipped");
        return;
    }
    if (*site != SECURE_NEW && !replace_instruction(site, SECURE_ORIG, SECURE_NEW)) {
        DEBUG_FUNCTION_LINE("NBA 2K13: failed to patch the redirector secure flag");
        return;
    }
    DEBUG_FUNCTION_LINE("NBA 2K13: plain-TCP redirector flag @%08x patched", (uint32_t) site);
    ShowNotification("NBA 2K13: online plain TCP patch applied");
}
