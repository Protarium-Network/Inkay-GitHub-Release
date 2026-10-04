#include "justdance_cert.h"

#include <string_view>
#include <coreinit/dynload.h>
#include <coreinit/title.h>
#include <coreinit/exception.h>
#include <coreinit/debug.h>
#include <coreinit/memorymap.h>
#include <cstdio>

#include "config.h"
#include "Notification.h"
#include "utils/logger.h"
#include "utils/replace_mem.h"
#include "utils/rpl_info.h"

using namespace std::string_view_literals;

namespace {
// Only ever run this for an actual game. wiiu_ua_engine_f.rpx is a *generic*
// UbiArt engine name; after a JD crash a stale RPL entry could linger into the
// Wii U Menu, and touching the JD2017 offset against that DSI'd the console
// (looked like an Aroma boot-loop). Wii U Menu / Mii Maker / H&S are all
// system titles (0x00050010'........); games are 0x00050000'.........
constexpr uint64_t TITLE_TYPE_MASK = 0xFFFFFFFF'00000000ull;
constexpr uint64_t TITLE_TYPE_GAME = 0x00050000'00000000ull;
// wiiu_ua_engine_f.rpx  (Just Dance 2017 UbiArt engine). Not pinned by hash: every
// candidate below is verified against the instruction bytes before anything is patched.
constexpr auto JD_RPX = "wiiu_ua_engine_f.rpx"sv;

// ssl_verify_cert_chain(SSL *s, STACK_OF(X509) *sk)  -- OpenSSL 1.0.2, static.
// Entry prologue; return 1 immediately so ssl3_get_server_certificate()'s
// "if (i <= 0)" never fires and s->verify_result stays X509_V_OK.
// The engine build differs per region AND per update (.text is shifted), so there is one
// address per known build. A console runs base+update, so the update's RPX is the one to match.
// To add a build: find the function that references
// the strings "ssl_client" and "ssl_server" in its wiiu_ua_engine_f.rpx.
struct Candidate { uint32_t addr; bool strict; };
// strict = also check the next 6 words of the prologue (identical across the EUR base/update builds), so an
// address that lands on some other function in a different build can't be mistaken for this one.
constexpr Candidate SSL_VERIFY_CERT_CHAIN[] = {
    {0x0457558c, true},  // EUR  WUP-P-BJ7P + update v32 (0005000E101EAA00), rpx sha1 87c7664f... - what actually runs on a console
    {0x0452a684, true},  // EUR  WUP-P-BJ7P base v0 only (title 00050000101EAA00), rpx sha1 279f4204...
    {0x0452af08, false}, // the (USA) build this patch was first written against, sha1 24334fb4... - unchanged, known to work
    // JD2018 base, EUR (00050000-10210C00) and USA (00050000-10211300) - same engine build,
    // byte-identical rpx (sha1 b3e27260...) for both regions, base title only (no update seen yet).
    {0x044f8cc0, true},
    // JD2019 update v64, EUR (0005000E-10217000) and USA (title 00050000-10217300) - byte-identical
    // rpx (sha1 4330046f...). No base-only (v0) rpx seen, so an unpatched v0 install just gets no patch.
    {0x04720a84, true},
};
constexpr uint32_t ORIG_TAIL[6] = {0x93c10098, 0x93e1009c, 0x900100a4, 0x7c7d1b78, 0x815d0098, 0x83ea0150};
constexpr uint32_t ORIG_0 = 0x9421ff60; // stwu r1, -0xa0(r1)
constexpr uint32_t ORIG_1 = 0x93a10094; // stw  r29, 0x94(r1)
constexpr uint32_t NEW_0  = 0x38600001; // li   r3, 1
constexpr uint32_t NEW_1  = 0x4e800020; // blr

// JD2019 only: force-unlock every customizable item (avatars, skins, portrait borders, ...).
// Uplay-reward unlocks are compiled out of the Wii U build (JD_UplayProgressHandler::checkUplayReward
// is #if ORBIS||DURANGO), so hook JD_CustomizableItemDatabaseEntry_Base::setCurrentStatus
// (`stw r4,0x10(r3); blr`, 4 callers: save load, reset-to-defaults, lock/unlock, unlock-fallback)
// so Locked(1) is stored as Unlocked(3). Hidden(2) stays hidden. The stub lives in the dead body of
// ssl_verify_cert_chain (never runs past its first two words once the cert patch is in).
// Takes effect when the save is loaded, i.e. from the 2nd boot of a brand-new profile.
constexpr uint32_t JD19_CERT = 0x04720a84;
constexpr uint32_t JD19_SET_STATUS = 0x032b1c0c;
constexpr uint32_t JD19_CAVE = JD19_CERT + 8;
constexpr uint32_t JD19_SET_ORIG[2] = {0x90830010, 0x4e800020}; // stw r4,0x10(r3); blr
constexpr uint32_t JD19_CAVE_CODE[5] = {
    0x2c040001, // cmpwi r4, 1        ; Locked?
    0x40820008, // bne   +8
    0x38800003, // li    r4, 3        ; -> Unlocked
    0x90830010, // stw   r4, 0x10(r3)
    0x4e800020, // blr
};
// b JD19_CAVE, from JD19_SET_STATUS (relative, so it holds wherever the rpx is loaded)
constexpr uint32_t JD19_BRANCH = 0x48000000 | ((JD19_CAVE - JD19_SET_STATUS) & 0x03fffffc);

void patch_jd19_unlocks(uint8_t *text, uint32_t textSize) {
    if (JD19_SET_STATUS + 8 - 0x0200'0000 > textSize) return;
    auto *set = reinterpret_cast<uint32_t *>(text + (JD19_SET_STATUS - 0x0200'0000));
    auto *cave = reinterpret_cast<uint32_t *>(text + (JD19_CAVE - 0x0200'0000));
    if (set[0] == JD19_BRANCH) return; // already hooked this boot
    if (set[0] != JD19_SET_ORIG[0] || set[1] != JD19_SET_ORIG[1]) return; // not the build we know
    for (int i = 0; i < 5; i++) // the cave is the tail of the (verified) ORIG_TAIL prologue
        if (!replace_instruction(&cave[i], ORIG_TAIL[i], JD19_CAVE_CODE[i])) return;
    replace_instruction(&set[0], JD19_SET_ORIG[0], JD19_BRANCH);
    DEBUG_FUNCTION_LINE("JD2019 unlock patch: setCurrentStatus hooked @%08x", (uint32_t)set);
    ShowNotification("Just Dance 2019: all avatars/items unlocked");
}

// ---- Just Dance 2015 (JustDance6, ITF framework, not UbiArt) ----
// EUR 00050000-10176F00 and USA 00050000-10179100 run the same update v16 rpx
// (cafe_ITF_AppFramework_f.rpx, sha1 29ca9cd7...). TLS is Nintendo's nlibcurl/NSSL (covered by
// the IOSU NoSSL patch), but UbiServices SDK 2.1.5 then re-checks the server cert itself
// (ubiservices::HttpCertificateValidator: issuer/CN pin + validity dates) and our *.ubi.com
// cert expired in 2015 -> "CA certificate has expired", the session call is retried forever.
constexpr uint64_t JD15_TITLES[] = {0x00050000'10176F00ull, 0x00050000'10179100ull};
constexpr auto JD15_RPX = "cafe_ITF_AppFramework_f.rpx"sv;
struct Jd15Patch { uint32_t addr, orig0, orig1; const char *what; };
constexpr Jd15Patch JD15_PATCHES[] = {
    {0x04b1d068, 0x9421fb58, 0xbe610474, "HttpCertificateValidator::validate"},   // "Couldn't match CA TSL/SSL certificate..."
    {0x04b1ce68, 0x9421ff50, 0x93c100a8, "HttpCertificateValidator::checkDates"}, // "CA certificate has expired..."
    // Uplay rewards (JD6REWARD01..04: mojo, avatar, Love Me Again mashup, Robot Rock) - the server
    // also returns them owned; this makes them owned even before/without the rewards request.
    {0x03e81508, 0x9421ffc0, 0x7c0802a6, "UplayWinService::HasReward"},
};
// REVERTED 2026-09-26: patched out 0x4d8eb9c (the generic "connection failed" event raiser,
// 13 call sites across the login flow) as a diagnostic to see if the console would proceed past
// its disconnect+retry instead of giving up. It did get further once (reached World Dance
// Floor loading before erroring), but on every later test - even after a full console reboot -
// the console just sits on the RDV connection exchanging PING only, forever, never sending
// LoginWithToken_V2 or anything else, until it silently times out client-side. That function is
// very likely also what the client relies on to notice a failed attempt and retry the login from
// scratch; disarming it removes the crash/quick-disconnect but leaves the client stuck instead.
// The real, non-masking fixes (RC4 re-keying per message, always reading callId, correct
// Register_V1/RegisterURLs_V1 responses) are in the server, not here - keep this disarmed only
// if a future test needs the same diagnostic again.

// RendezVousSDK's generic RMC response dispatcher (used by every protocol, not just
// SimpleAuthentication) ends in a hard `twu r31,r31` trap when a response doesn't match any
// of the method names that particular call site expects - a "this should never happen on the
// real Ubisoft server" assertion. Console-confirmed 2026-09-26 (crash report: PC in this trap,
// reached from SimpleAuthenticationProtocol::Register_V1's response check, right after our
// LoginWithToken_V2 reply, with zero further packets logged server-side) that OUR server hits
// this despite the wire format matching the RPX's own read routines byte for byte - our custom
// server will likely never be byte-perfect in every corner case, so instead of chasing each one,
// disarm the assertion itself. Every one of its 31 call sites discards the return value right
// after calling it (verified at the JD2015 one), so turning the trap into a no-op just makes an
// unrecognized response a silent skip instead of a crash - functionally equivalent to what the
// trap's own "li r3,0; <trap>; blr" would have returned had it not crashed.
constexpr uint32_t RMC_TRAP_ADDR = 0x04d4e62c;
constexpr uint32_t RMC_TRAP_ORIG = 0x7ffff808; // twu r31, r31
constexpr uint32_t RMC_TRAP_NOP = 0x60000000;  // nop

// Crash reporter (debug): JD2015 dies silently right after the RDV login. On DSI/ISI/program
// exceptions, show the faulting PC/LR + back-trace as RPX addresses (0x02000000-based, same
// numbering as the RE tools) via OSFatal, so the console screen tells us where it died.
// ponytail: debug-only, remove once JD2015 online is stable.
uint32_t jd15Text = 0, jd15TextSize = 0;
uint32_t rpxAddr(uint32_t a) { return (a >= jd15Text && a < jd15Text + jd15TextSize) ? a - jd15Text + 0x0200'0000 : a; }
BOOL jd15Crash(OSContext *ctx, const char *what) {
    static char buf[768];
    int n = snprintf(buf, sizeof buf, "JD2015 %s\nPC %08X LR %08X\nDAR %08X DSISR %08X\nr3 %08X r4 %08X r31 %08X\nstack:",
                     what, rpxAddr(ctx->srr0), rpxAddr(ctx->lr), ctx->dar, ctx->dsisr, ctx->gpr[3], ctx->gpr[4], ctx->gpr[31]);
    uint32_t sp = ctx->gpr[1];
    for (int i = 0; i < 14 && n < (int)sizeof buf - 12; i++) {
        if (!sp || (sp & 3) || !OSIsAddressValid(sp) || !OSIsAddressValid(sp + 4)) break;
        uint32_t next = *(uint32_t *)sp;
        if (!next || (next & 3) || !OSIsAddressValid(next + 4)) break;
        n += snprintf(buf + n, sizeof buf - n, "%s%08X", i % 5 ? " " : "\n", rpxAddr(*(uint32_t *)(next + 4)));
        sp = next;
    }
    OSFatal(buf);
    return FALSE;
}
BOOL jd15Dsi(OSContext *c) { return jd15Crash(c, "DSI"); }
BOOL jd15Isi(OSContext *c) { return jd15Crash(c, "ISI"); }
BOOL jd15Prog(OSContext *c) { return jd15Crash(c, "PROGRAM"); }

void patch_justdance2015() {
    const uint64_t tid = OSGetTitleID();
    bool isJd15 = false;
    for (auto t : JD15_TITLES) isJd15 |= (tid == t);
    if (!isJd15) return;
    auto rpx = search_for_rpl(JD15_RPX);
    if (!rpx) return;
    jd15Text = rpx->textAddr; jd15TextSize = rpx->textSize;
    OSSetExceptionCallbackEx(OS_EXCEPTION_MODE_GLOBAL_ALL_CORES, OS_EXCEPTION_TYPE_DSI, jd15Dsi);
    OSSetExceptionCallbackEx(OS_EXCEPTION_MODE_GLOBAL_ALL_CORES, OS_EXCEPTION_TYPE_ISI, jd15Isi);
    OSSetExceptionCallbackEx(OS_EXCEPTION_MODE_GLOBAL_ALL_CORES, OS_EXCEPTION_TYPE_PROGRAM, jd15Prog);
    int applied = 0;
    for (const auto &p : JD15_PATCHES) {
        const uint32_t off = p.addr - 0x0200'0000;
        if (off + 8 > rpx->textSize) continue;
        auto *f = reinterpret_cast<uint32_t *>(rpx->textAddr + off);
        if (f[0] == NEW_0 && f[1] == NEW_1) continue; // already done this boot
        if (f[0] != p.orig0 || f[1] != p.orig1) {
            DEBUG_FUNCTION_LINE("JD2015: %s not found @%08x (%08x %08x) - other build?", p.what, (uint32_t)f, f[0], f[1]);
            continue;
        }
        replace_instruction(&f[0], p.orig0, NEW_0);
        replace_instruction(&f[1], p.orig1, NEW_1);
        DEBUG_FUNCTION_LINE("JD2015: %s -> return 1 @%08x", p.what, (uint32_t)f);
        applied++;
    }
    {
        const uint32_t off = RMC_TRAP_ADDR - 0x0200'0000;
        if (off + 4 <= rpx->textSize) {
            auto *f = reinterpret_cast<uint32_t *>(rpx->textAddr + off);
            if (*f == RMC_TRAP_NOP) applied++; // already done this boot
            else if (*f == RMC_TRAP_ORIG) {
                replace_instruction(f, RMC_TRAP_ORIG, RMC_TRAP_NOP);
                DEBUG_FUNCTION_LINE("JD2015: RMC response-mismatch trap disarmed @%08x", (uint32_t)f);
                applied++;
            } else {
                DEBUG_FUNCTION_LINE("JD2015: RMC trap not found @%08x (%08x) - other build?", (uint32_t)f, *f);
            }
        }
    }
    if (applied) ShowNotification("Just Dance 2015: online patches applied");
}

// ---- Just Dance 2016 (UbiArt engine, same wiiu_ua_engine_f.rpx name as 2017-2019 but a
// distinct compiler build - neither ssl_verify_cert_chain's prologue nor its unlock story match
// those years, so it gets its own dedicated patch, same shape as patch_justdance2015() above).
// EUR (00050000-101B9800) and USA (00050000-101B9000) ship the byte-identical rpx (sha1
// c01e7af14ad3174e76b4856ef8481efdd07c3001 of the decompressed .text) - one offset covers both
// regions, no separate USA-only entry needed.
constexpr uint64_t JD16_TITLES[] = {0x00050000'101B9800ull, 0x00050000'101B9000ull};

// ssl_verify_cert_chain(SSL*, STACK_OF(X509)*) - found by decompiling the one function in the
// rpx that calls X509_STORE_CTX_init(&ctx, s->ctx->cert_store, x, sk) with exactly this 4-arg
// shape, right after sk_X509_num/sk_X509_value on the incoming chain (ctx.error is stored into
// s->verify_result right before it returns, at the very end). Same OpenSSL logic as 2017-2019
// but a different compiler build entirely: entry saves LR explicitly (mflr r0) and uses r30/r31
// with a -0x98 frame instead of the shared SSL_VERIFY_CERT_CHAIN[] candidates' r29/-0xa0
// prologue, so it can't just be another entry in that table.
constexpr uint32_t JD16_CERT = 0x04009050;
constexpr uint32_t JD16_CERT_ORIG[4] = {0x7c0802a6, 0x9421ff68, 0x93c10090, 0x93e10094};

// Force-unlock every map + avatar via the dev cheat the game itself ships in retail
// (JD_CheatCodeUnlockAllMaps - source JD_CheatCodes.cpp: active() calls JD_SongDatabase::
// unlockAll() + JD_AvatarDatabase::unlockAll()). It's the ONLY cheat code compiled into a
// retail/ITF_FINAL build - the other four (EndMap, AddFakePlayer, LocaMode, PleoInfo) are
// #ifndef ITF_FINAL in JD_CheatManager's constructor - but it never fires in practice:
// JD_CheatCode::check() bails out whenever !m_isEnable (source JD_CheatCodes.cpp:36), and
// nothing in a retail build ever enables it except the phone-pairing device-selection screen,
// which disables it again the moment that screen closes. Rather than synthesize a call during
// early boot (active() reaches into several other manager singletons - JD_SongDatabase,
// JD_AvatarDatabase, JD_TrackingManager - that aren't guaranteed constructed yet at that point,
// a real crash risk), patch check() itself to ignore m_isEnable and fire the moment
// m_isActivated is still false. This only ever runs from the game's OWN per-frame
// JD_CheatManager::update() -> checkCheatCodes() -> check() -> active() chain (confirmed via
// the vtable: update is JD_CheatManager's own +0x64 slot, called every frame once full boot is
// done and every manager exists), exactly as if the player had entered the real input sequence.
// m_isActivated flips true on the first activation (offset +8, confirmed by decompiling
// check()), so this fires exactly once and is inert (returns false) every frame after.
constexpr uint32_t JD16_CHECK = 0x02708644;
constexpr uint32_t JD16_CHECK_ORIG[7] = {
    0x7c0802a6, 0x90010004, 0x7c671b78, 0x9421fff8, 0x81430004, 0x2c0a0000, 0x38c00000,
};
constexpr uint32_t JD16_CHECK_NEW[7] = {
    0x80030008, // lwz  r0, 0x8(r3)   ; r0 = m_isActivated
    0x2c000000, // cmpwi r0, 0
    0x4082000c, // bne  +0xc          ; already activated -> return false
    0x38600001, // li   r3, 1
    0x4e800020, // blr
    0x38600000, // li   r3, 0
    0x4e800020, // blr
};

void patch_justdance2016() {
    const uint64_t tid = OSGetTitleID();
    bool isJd16 = false;
    for (auto t : JD16_TITLES) isJd16 |= (tid == t);
    if (!isJd16) return;
    auto rpx = search_for_rpl(JD_RPX);
    if (!rpx) return;

    if (JD16_CERT - 0x0200'0000 + 4 * sizeof(uint32_t) <= rpx->textSize) {
        auto *f = reinterpret_cast<uint32_t *>(rpx->textAddr + (JD16_CERT - 0x0200'0000));
        if (f[0] == NEW_0 && f[1] == NEW_1) {
            // already patched this boot
        } else if (f[0] == JD16_CERT_ORIG[0] && f[1] == JD16_CERT_ORIG[1] &&
                   f[2] == JD16_CERT_ORIG[2] && f[3] == JD16_CERT_ORIG[3]) {
            replace_instruction(&f[0], JD16_CERT_ORIG[0], NEW_0);
            replace_instruction(&f[1], JD16_CERT_ORIG[1], NEW_1);
            DEBUG_FUNCTION_LINE("JD2016 cert patch: ssl_verify_cert_chain neutered @%08x", (uint32_t)f);
            ShowNotification("Just Dance 2016: TLS cert check bypassed");
        } else {
            DEBUG_FUNCTION_LINE("JD2016 cert patch: ssl_verify_cert_chain not found @%08x (%08x %08x) - other build?",
                                 (uint32_t)f, f[0], f[1]);
        }
    }

    // DISABLED 2026-09-27: fires on the very first per-frame checkCheatCodes() call, which
    // turned out to run before the "press 1 to start" attract screen ever responds to input -
    // active() reaches into JD_SongDatabase/JD_AvatarDatabase/JD_TrackingManager singletons
    // that (unlike what the update()-timing analysis assumed) are apparently NOT guaranteed
    // constructed by then, and something in that chain wedges the input dispatch. Console-
    // confirmed regression: console sat unresponsive on "press 1 to start" with this patch
    // active, cert-only build (this whole block skipped) needs retesting before re-enabling.
    // Needs a later, confirmed-safe trigger point (e.g. gated on a real gameplay GameScreen
    // being active) before this is safe to ship again.
    (void)JD16_CHECK; (void)JD16_CHECK_ORIG; (void)JD16_CHECK_NEW;
}
}

void patch_justdance_cert() {
    if (!Config::connect_to_network) return;

    // Never touch a system title (Wii U Menu, Mii Maker, H&S, ...) - a stale
    // engine RPL entry lingering there after a JD crash was the boot-loop.
    if ((OSGetTitleID() & TITLE_TYPE_MASK) != TITLE_TYPE_GAME) return;

    patch_justdance2015();
    patch_justdance2016();

    auto rpx = search_for_rpl(JD_RPX);
    if (!rpx) return; // no UbiArt engine RPX loaded - not a Just Dance game

    // These are JD2017-specific .text offsets. The SAME engine RPX name
    // (wiiu_ua_engine_f.rpx) is used by JD2015/2016/2018/2019 and other UbiArt
    // Wii U titles, whose .text is a different size. Dereferencing an offset
    // past the end of the mapping -> DSI -> console hang (intermittent, looked
    // like an Aroma splash freeze). Bounds-check each candidate first.
    uint32_t *f = nullptr;
    for (const auto &cand : SSL_VERIFY_CERT_CHAIN) {
        const uint32_t off = cand.addr - 0x0200'0000;
        if (off + 8 * sizeof(uint32_t) > rpx->textSize) continue;
        auto *c = reinterpret_cast<uint32_t *>(rpx->textAddr + off);
        if (c[0] == NEW_0 && c[1] == NEW_1) {
            if (cand.addr == JD19_CERT) patch_jd19_unlocks(reinterpret_cast<uint8_t *>(rpx->textAddr), rpx->textSize);
            return; // already patched this boot
        }
        if (c[0] == ORIG_0 && c[1] == ORIG_1) {
            bool ok = true;
            if (cand.strict) {
                for (int i = 0; i < 6; i++) ok = ok && c[2 + i] == ORIG_TAIL[i];
            }
            if (ok) {
                f = c;
                break;
            }
        }
    }
    if (!f) {
        DEBUG_FUNCTION_LINE("JD cert patch: no known ssl_verify_cert_chain in this engine build (.text %08x) - skipping",
                            rpx->textSize);
        return; // different UbiArt build - stay quiet, this fires every app-start
    }

    replace_instruction(&f[0], ORIG_0, NEW_0);
    replace_instruction(&f[1], ORIG_1, NEW_1);
    DEBUG_FUNCTION_LINE("JD cert patch: ssl_verify_cert_chain neutered @%08x", (uint32_t)f);
    ShowNotification("Just Dance: TLS cert check bypassed");
    if (reinterpret_cast<uint32_t>(f) == rpx->textAddr + (JD19_CERT - 0x0200'0000))
        patch_jd19_unlocks(reinterpret_cast<uint8_t *>(rpx->textAddr), rpx->textSize);
}
