#include "bo2_auth.h"

#include <coreinit/title.h>
#include <string_view>

#include "config.h"
#include "Notification.h"
#include "sysconfig.h"
#include "utils/logger.h"
#include "utils/replace_mem.h"
#include "utils/rpl_info.h"

using namespace std::string_view_literals;

#define BO2_USA_TITLE_ID  0x000500001010cf00 // USA / NTSC-U
#define BO2_EUR_TITLE_ID  0x0005000010113400 // EUR - English / UK
#define BO2_ESIT_TITLE_ID 0x0005000010113500 // EUR - Spanish + Italian
#define BO2_DE_TITLE_ID   0x0005000010113700 // EUR - German
#define BO2_JPN_TITLE_ID  0x000500001011b400 // JPN

// t6mp_cafef_rpl.rpl from BO2 update v128, SHA-256:
// 3B30AB9F0D487C9508DA81E1547A64FD95DC6E58A97724ECF57EBBEEE04FF63F
static const uint32_t RSA_VERIFY_BRANCH = 0x02a2e69c;
static const uint32_t ORIGINAL_BNE      = 0x40820070; // bne 0x02a2e70c
static const uint32_t BYPASS_BRANCH     = 0x48000070; // b   0x02a2e70c

void patch_bo2_auth() {
    if (!Config::connect_to_network) return;

    const uint64_t title_id = OSGetTitleID();
    if (title_id != BO2_USA_TITLE_ID && title_id != BO2_EUR_TITLE_ID &&
        title_id != BO2_ESIT_TITLE_ID && title_id != BO2_DE_TITLE_ID &&
        title_id != BO2_JPN_TITLE_ID) return;

    const auto multiplayer = search_for_rpl("t6mp_cafef_rpl.rpl"sv);
    if (!multiplayer) {
        DEBUG_FUNCTION_LINE("BO2 auth patch skipped: multiplayer RPL not loaded");
        return;
    }

    auto *branch = static_cast<uint32_t *>(rpl_addr(*multiplayer, RSA_VERIFY_BRANCH));
    if (replace_instruction(branch, ORIGINAL_BNE, BYPASS_BRANCH)) {
        DEBUG_FUNCTION_LINE("BO2 auth RSA compatibility patch applied");
        ShowNotification("BO2: authentication compatibility patch applied");
    } else if (*branch != BYPASS_BRANCH) {
        DEBUG_FUNCTION_LINE("BO2 auth patch skipped: unexpected instruction %08x", *branch);
        ShowNotification("BO2: authentication patch address mismatch");
    }
}
