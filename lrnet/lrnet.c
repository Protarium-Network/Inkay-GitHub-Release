// lrnet.c - two-player rooms for Lost Reavers offline.
//
// Replaces the NEX matchmaking/P2P layer of OnlineWiiUNexSystemWiiU (which needs Nintendo's servers) with a small
// UDP protocol to the offline server (server/lobby.js), which keeps the rooms and relays packets between players.
// The game's own code above that layer is unchanged: UE3's net driver still sends through SendTo/RecvFrom by NEX
// principal id (PID), room messages still go through InternalSendParticipantInSession, and received packets are
// put into the game's own OnlineWiiUPacketAllocator queues exactly where the NEX DirectStream callbacks put them.
//
// One source for both builds:
//  * Cemu (LR_CEMU): compiled freestanding and linked at 0x02e6d210, over ParticipantProcess..MatchmakeProcess,
//    which only Process() called; tools/build-lrnet.js turns it into cemu-pack/patch_net.asm.
//  * Aroma plugin: compiled into the plugin; lr_code_off = where the console loaded the game's code.
// OS imports (socket, mutex) are relocated by the loader, so their addresses are read at run time from a "bl" in
// game code that calls them (lr_import).
//
// Linked (v16) addresses of everything used are in the LRA_* constants. Offsets into OnlineWiiUNexSystemWiiU:
//   +0x250 current UOnlineWiiUContext   +0x244 -> TArray<UOnlineWiiUSession*> search pool   +0x2e8 my PID
//   +0x47b8 search output TArray*   +0x47c4 session being created   +0x47cc gathering id to join
//   +0x47d8 station list (0x18 each: [0] CID, [1] context, [2] pending, [3] valid), +0x47dc its size
//   +0x47f4/+0x4780/+0x485c in-session flags   +0x47fc owner PID   +0x4800 gathering id (IsMatchmakeSession)
//   +0x4818 participants (0x34 each: [0] CID, [1] PID, [2..] name UTF-16 x17, [11] valid, [12] friend)
//   +0x481c valid[], +0x4820 updated[]   +0x482c update bits   +0x4830/+0x4834 counts   +0x4838 my index
//   +0x483c capacity   +0x4840 "participants updated" (CheckUpdateParticipantsInSession)
//   +0x14930 UE3 packet queue (RecvFrom)   +0x149a0/+0x149bc user packet queues   +0x149e0 OSFastMutex
#include "lrnet.h"

typedef unsigned int u32;
typedef int s32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef long long s64;

#ifdef LR_CEMU
#define LR_OFF 0u
u32 lr_code_off = 0;
#else
u32 lr_code_off = 0;
#define LR_OFF lr_code_off
#endif

#define W(a) (*(volatile u32 *) (a))
#define GFN(a, T) ((T) (void *) ((u32) (a) + LR_OFF))

// ---- Game addresses (v16, as linked) -----------------------------------------------------------------------------
#define LRA_QUEUE_PROCESS   0x02e86fb8 // OnlineWiiUQueueProcess::Process(this)
#define LRA_PKT_ADD         0x02e61f14 // OnlineWiiUPacketAllocator::Add(this, int pid, u32 len, const void*, int)
#define LRA_SET_RESULT      0x02e5f734 // UOnlineWiiUContext::SetResult(ctx, int)
#define LRA_GET_RESULT      0x02e60294 // UOnlineWiiUContext::GetResult(ctx)
#define LRA_APP_REALLOC     0x0202f2f0 // appRealloc(void*, u32 size, u32 align)
#define LRA_NEX_SLEEP       0x0320fbfc // nn::nex::Platform::Sleep(ms), as the original Process ends with
// call sites ("bl import") the import addresses are read from
#define LRS_SOCKET          0x02f417f0 // socket       in FSocketSubsystemWiiU::CreateDGramSocket
#define LRS_BIND            0x02f40d18 // bind         in FSocketWiiU::Bind
#define LRS_SENDTO          0x02f4116c // sendto       in FSocketWiiU::SendTo
#define LRS_RECVFROM        0x02f41250 // recvfrom     in FSocketWiiU::RecvFrom
#define LRS_SETSOCKOPT      0x02f41424 // setsockopt   in FSocketWiiU::SetNonBlocking
#define LRS_SELECT          0x02f40e18 // select       in FSocketWiiU::HasPendingConnection
#define LRS_RECV            0x02f41290 // recv         in FSocketWiiU::Recv
#define LRS_LASTERR         0x02ef4fa0 // socketlasterr in curl_sockopt (SnowHttpSystem)
#define LR_BUILD            0x0016     // shown in the 0x30 debug line (plugin v0.16)
#define LRS_LOCK            0x02e73ebc // OSFastMutex_Lock   in OnlineWiiUNexSystemWiiU::RecvFrom
#define LRS_UNLOCK          0x02e73f28 // OSFastMutex_Unlock in OnlineWiiUNexSystemWiiU::RecvFrom

typedef s32 (*fn_socket)(s32, s32, s32);
typedef s32 (*fn_bind)(s32, const void *, s32);
typedef s32 (*fn_sendto)(s32, const void *, s32, s32, const void *, s32);
typedef s32 (*fn_recvfrom)(s32, void *, s32, s32, void *, s32 *);
typedef s32 (*fn_setsockopt)(s32, s32, s32, const void *, s32);
typedef s32 (*fn_select)(s32, u32 *, u32 *, u32 *, s32 *);
typedef s32 (*fn_recv)(s32, void *, s32, s32);
typedef s32 (*fn_lasterr)(void);
typedef void (*fn_mutex)(void *);
typedef void (*fn_this)(u32);
typedef s32 (*fn_add)(u32, s32, u32, const void *, s32);
typedef void (*fn_setres)(u32, s32);
typedef s32 (*fn_getres)(u32);
typedef u32 (*fn_realloc)(u32, u32, u32);
typedef void (*fn_v1)(u32);
typedef void (*fn_v3)(u32, s32, s32);
typedef void (*fn_v4)(u32, s32, s32, s32);

// ---- Protocol (all big-endian; see server/lobby.js) --------------------------------------------------------------
#define LR_MAGIC 0x4c524e31u // "LRN1"
enum {
    T_CREATE = 2, T_FIND = 3, T_JOIN = 4, T_LEAVE = 5, T_OPEN = 6, T_KEEP = 7, T_DATA = 8, T_LOG = 9, T_UPDATE = 10,
    R_CREATED = 0x82, R_LIST = 0x83, R_JOINED = 0x84, R_MEMBERS = 0x85, R_DATA = 0x88,
};
#define MAX_MEMBERS 4
// Time is counted in Process() calls: the network thread loops Process + 3 ms sleep (~350 a second in Cemu).
// (The timebase via mftb/mftbu compared wrongly in Cemu's recompiled code: keepalives never went out.)
#define TICKS_PER_SEC_P 350u

// Debug counters (read with tools/cemu-peek.ps1 at the lr_dbg symbol): Process calls, polls finished,
// keepalives sent, last select() and recvfrom() results.
u32 lr_dbg[8];
static s32 g_sock = -1;
static u32 g_selOk = 0; // select() has worked at least once
static u32 g_ready = 0, g_failed = 0;
static u32 g_ip = 0x7f000001; // 127.0.0.1 (Cemu); the plugin sets the PC's address
static u32 g_port = 8765;
static u32 g_pid = 0, g_gid = 0, g_inRoom = 0, g_owner = 0;
static u32 g_seq = 0;
static u32 g_waitType = 0, g_waitSeq = 0, g_gotReply = 0;
static u32 g_tick = 0, g_waitStart = 0, g_lastKeepTick = 0, g_lastSend = 0;
static u32 g_nMem = 0, g_mem[MAX_MEMBERS];
static u16 g_names[MAX_MEMBERS][17];
static fn_socket p_socket;
static fn_bind p_bind;
static fn_sendto p_sendto;
static fn_recvfrom p_recvfrom;
static fn_setsockopt p_setsockopt;
static fn_select p_select;
static fn_recv p_recv;
static fn_lasterr p_lasterr;
static u32 g_lastErr = 0, g_lastSl = 0;
static fn_mutex p_lock, p_unlock;
// Cemu: the buffers go over two more functions that are dead with these hooks (PhaseFindMatchmakeSessionWait and
// PhaseLoginMatchmakeSessionWait are only ever queued by the replaced Start phases); see tools/build-lrnet.js.
#ifdef LR_CEMU
#define BUF_A __attribute__((section(".lrbufA")))
#define BUF_B __attribute__((section(".lrbufB")))
#else
#define BUF_A
#define BUF_B
#endif
static u8 g_tx[1412] BUF_A; // max packet: 8 header + 4 pid + 1400 payload
#ifdef LR_CEMU
static u8 g_rx[1536] BUF_A;
#else
static u8 g_rx[1536] __attribute__((aligned(64))); // IOS-friendly on a console: 64-byte aligned and sized
#endif
static u8 g_reply[900] BUF_B;
static u32 g_replyLen = 0;

#ifdef LR_CEMU
// Freestanding build: the compiler may emit calls to these.
void *memcpy(void *d, const void *s, unsigned long n) {
    u8 *a = (u8 *) d;
    const u8 *b = (const u8 *) s;
    while (n--) *a++ = *b++;
    return d;
}
void *memset(void *d, int c, unsigned long n) {
    u8 *a = (u8 *) d;
    while (n--) *a++ = (u8) c;
    return d;
}
#endif
static void cpy(void *d, const void *s, u32 n) {
    volatile u8 *a = (volatile u8 *) d;
    const volatile u8 *b = (const volatile u8 *) s;
    while (n--) *a++ = *b++;
}
static void put32(u8 *p, u32 v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }
static u32 get32(const u8 *p) { return ((u32) p[0] << 24) | ((u32) p[1] << 16) | ((u32) p[2] << 8) | p[3]; }


// Target of the "bl" at a linked game address (0 if it is not a bl). Cemu links imports as "bla" (absolute,
// AA bit set) to its own stubs; the console loader uses a relative bl.
static u32 lr_import(u32 site) {
    u32 a = site + LR_OFF, ins = W(a);
    if ((ins & 0xfc000001u) != 0x48000001u) return 0;
    s32 li = (s32) (ins & 0x03fffffcu);
    if (li & 0x02000000) li |= (s32) 0xfc000000;
    return (ins & 2) ? (u32) li : a + (u32) li;
}

void lr_set_server(u32 ip, u32 port) {
    g_ip   = ip;
    g_port = port;
}

static s32 net_init(void) {
    if (g_ready) return 1;
    if (g_failed) return 0;
    p_socket     = (fn_socket) (void *) lr_import(LRS_SOCKET);
    p_bind       = (fn_bind) (void *) lr_import(LRS_BIND);
    p_sendto     = (fn_sendto) (void *) lr_import(LRS_SENDTO);
    p_recvfrom   = (fn_recvfrom) (void *) lr_import(LRS_RECVFROM);
    p_setsockopt = (fn_setsockopt) (void *) lr_import(LRS_SETSOCKOPT);
    p_select     = (fn_select) (void *) lr_import(LRS_SELECT);
    p_recv       = (fn_recv) (void *) lr_import(LRS_RECV);
    p_lasterr    = (fn_lasterr) (void *) lr_import(LRS_LASTERR);
    p_lock      = (fn_mutex) (void *) lr_import(LRS_LOCK);
    p_unlock     = (fn_mutex) (void *) lr_import(LRS_UNLOCK);
    if (!p_socket || !p_bind || !p_sendto || !p_recvfrom || !p_setsockopt || !p_select || !p_lock || !p_unlock) {
        g_failed = 1;
        return 0;
    }
    s32 s = p_socket(2 /*AF_INET*/, 2 /*SOCK_DGRAM*/, 17 /*IPPROTO_UDP*/);
    if (s < 0) {
        g_failed = 1;
        return 0;
    }
    s32 one = 1;
    p_setsockopt(s, -1 /*SOL_SOCKET*/, 0x1016 /*SO_NONBLOCK*/, &one, 4);
    u8 sa[16];
    for (int i = 0; i < 16; i++) sa[i] = 0;
    sa[1] = 2; // sin_family (u16) AF_INET, port 0 = any
    p_bind(s, sa, 16);
    g_sock  = s;
    g_ready = 1;
    return 1;
}

static void tx(u32 type, u32 len) { // g_tx[8..] filled by the caller
    if (!net_init()) return;
    put32(g_tx, LR_MAGIC);
    put32(g_tx + 4, type);
    u8 sa[16];
    for (int i = 0; i < 16; i++) sa[i] = 0;
    sa[1] = 2;
    sa[2] = (u8) (g_port >> 8);
    sa[3] = (u8) g_port;
    put32(sa + 4, g_ip);
    p_sendto(g_sock, g_tx, (s32) (8 + len), 0, sa, 16);
}
static void tx1(u32 type, u32 a) {
    put32(g_tx + 8, a);
    tx(type, 4);
}
static void tx2(u32 type, u32 a, u32 b) {
    put32(g_tx + 8, a);
    put32(g_tx + 12, b);
    tx(type, 8);
}
// Debug line in the server log: "NET <code> a b c".
static void dbg(u32 code, u32 a, u32 b, u32 c) {
    put32(g_tx + 8, code);
    put32(g_tx + 12, a);
    put32(g_tx + 16, b);
    put32(g_tx + 20, c);
    tx(T_LOG, 16);
}

// ---- Participant table ------------------------------------------------------------------------------------------
static void apply_members(u32 self) {
    s32 cap = (s32) W(self + 0x483c);
    u32 tab = W(self + 0x4818), valid = W(self + 0x481c), upd = W(self + 0x4820);
    u32 st = W(self + 0x47d8);
    s32 stCap = (s32) W(self + 0x47dc);
    if (cap <= 0 || !tab || !valid || !upd) return;
    if (cap > MAX_MEMBERS) cap = MAX_MEMBERS;
    u32 changed = 0, me = 0;
    for (s32 i = 0; i < cap; i++) {
        u32 e = tab + (u32) i * 0x34;
        u32 pid = (u32) i < g_nMem ? g_mem[i] : 0;
        u32 was = W(valid + i * 4) ? W(e + 4) : 0;
        if (pid != was) {
            changed = 1;
            W(upd + i * 4) = 1;
        }
        if (pid) {
            W(e + 0) = pid; // CID = PID here
            W(e + 4) = pid;
            cpy((void *) (e + 8), g_names[i], 0x22);
            W(e + 0x2c) = 1;
            W(e + 0x30) = 0;
            W(valid + i * 4) = 1;
            if (pid == g_pid) me = (u32) i;
        } else {
            for (u32 k = 0; k < 0x34; k += 4) W(e + k) = 0;
            W(valid + i * 4) = 0;
        }
        if (st && i < stCap) {
            u32 se = st + (u32) i * 0x18;
            W(se + 0)  = pid;
            W(se + 8)  = 0;
            W(se + 12) = pid ? 1 : 0;
        }
    }
    W(self + 0x4830) = g_nMem;
    W(self + 0x4834) = g_nMem;
    W(self + 0x4838) = me;
    W(self + 0x47fc) = g_owner;
    if (changed) {
        W(self + 0x4840) = 1;
        W(self + 0x482c) = W(self + 0x482c) | 6;
    }
}

// MEMBERS / JOINED body: gid, owner, n, then n x (pid, 16-byte name)
static void read_members(const u8 *p, u32 len) {
    if (len < 12) return;
    u32 n = get32(p + 8);
    if (n > MAX_MEMBERS) n = MAX_MEMBERS;
    if (len < 12 + n * 20) return;
    g_owner = get32(p + 4);
    g_nMem  = n;
    for (u32 i = 0; i < MAX_MEMBERS; i++) {
        g_mem[i] = 0;
        for (u32 k = 0; k < 17; k++) g_names[i][k] = 0;
    }
    for (u32 i = 0; i < n; i++) {
        const u8 *m = p + 12 + i * 20;
        g_mem[i]    = get32(m);
        for (u32 k = 0; k < 16 && m[4 + k]; k++) g_names[i][k] = m[4 + k];
    }
}

static void deliver(u32 self, u32 src, const u8 *d, u32 len) {
    u32 q = 0x14930; // UE3 net driver packets
    if (len > 0x20 && d[0] == 'W' && d[1] == 'U' && d[2] == 'E' && d[3] == 'P' && get32(d + 8) < get32(d + 4))
        q = get32(d + 0x18) == 0 ? 0x149a0 : 0x149bc; // IsUserPacket: room messages
    p_lock((void *) (self + 0x149e0));
    GFN(LRA_PKT_ADD, fn_add)(self + q, (s32) src, len, d, 1);
    p_unlock((void *) (self + 0x149e0));
}

static void poll(u32 self) {
    if (!g_ready) return;
    for (int n = 0; n < 64; n++) {
        // Never block (this runs on the game's network thread): only read when select says data is waiting.
        // (SO_NONBLOCK / MSG_DONTWAIT alone did not stop recvfrom from blocking in Cemu.)
        u32 mask = 1u << g_sock;
        s32 tv[2] = {0, 0};
        s32 sel = g_sock >= 32 ? -1 : p_select(g_sock + 1, &mask, 0, 0, tv);
        lr_dbg[3] = (u32) sel;
        // select failing (< 0) on a console: the socket is non-blocking there, so read anyway.
        if (sel == 0 || (sel < 0 && g_selOk)) break;
        if (sel > 0) g_selOk = 1;
        u8 sa[16];
        s32 sl = 16;
        // flags 0: the console's nsysnet recvfrom fails (-1) with MSG_DONTWAIT (0x20 is wut's emulated flag, not
        // the system's). select said data is waiting, and the socket is SO_NONBLOCK, so this cannot block.
        s32 r = p_recvfrom(g_sock, g_rx, sizeof(g_rx), 0, sa, &sl);
        g_lastSl = (u32) sl;
        if (r < 0) {
            g_lastErr = p_lasterr ? (u32) p_lasterr() : 0xeeee;
            // the reply can only come from the server: plain recv needs no address argument
            if (p_recv) r = p_recv(g_sock, g_rx, sizeof(g_rx), 0);
            if (r < 0 && p_lasterr) g_lastErr = (g_lastErr << 16) | ((u32) p_lasterr() & 0xffff);
        }
        lr_dbg[4] = (u32) r;
        if (r < 8) break;
        lr_dbg[6]++;
        if (get32(g_rx) != LR_MAGIC) continue;
        u32 type = get32(g_rx + 4), len = (u32) r - 8;
        const u8 *b = g_rx + 8;
        if (type == R_DATA) {
            if (g_inRoom && len >= 4) deliver(self, get32(b), b + 4, len - 4);
        } else if (type == R_MEMBERS) {
            if (g_inRoom && len >= 12 && get32(b) == g_gid) {
                read_members(b, len);
                apply_members(self);
            }
        } else if (type == g_waitType && len >= 8 && get32(b) == g_waitSeq) {
            u32 c = len < sizeof(g_reply) ? len : sizeof(g_reply);
            cpy(g_reply, b, c);
            g_replyLen = c;
            g_gotReply = 1;
        }
    }
    lr_dbg[1]++;
    if (g_inRoom && g_tick - g_lastKeepTick > TICKS_PER_SEC_P) {
        g_lastKeepTick = g_tick;
        tx1(T_KEEP, g_gid);
        lr_dbg[2]++;
    }
}

// Phase helper: send a request once, then 0 = still waiting, 1 = reply in g_reply, -1 = timed out.
static s32 request(u32 self, u32 type, u32 replyType, const u32 *args, u32 nargs, u32 timeoutTicks) {
    if (!g_waitType) {
        if (!net_init()) return -1;
        g_waitType  = replyType;
        g_waitSeq   = ++g_seq;
        g_gotReply  = 0;
        g_waitStart = g_lastSend = g_tick;
        put32(g_tx + 8, g_waitSeq);
        for (u32 i = 0; i < nargs; i++) put32(g_tx + 12 + i * 4, args[i]);
        tx(type, 4 + nargs * 4);
        return 0;
    }
    poll(self);
    if (g_gotReply) {
        g_waitType = 0;
        return 1;
    }
    if (g_tick - g_waitStart > timeoutTicks) {
        g_waitType = 0;
        return -1;
    }
    // resend every half second (UDP); each resend reports receive state to the server log
    // ("NET log ... 0x30 <last select> <last recvfrom/recv> <build<<16 | packets read>" then
    //  "0x31 <errors: recvfrom<<16 | recv> <fromlen after the call> <socket fd>")
    if (g_tick - g_lastSend > TICKS_PER_SEC_P / 2) {
        g_lastSend = g_tick;
        dbg(0x30, lr_dbg[3], lr_dbg[4], (LR_BUILD << 16) | (lr_dbg[6] & 0xffff));
        dbg(0x31, g_lastErr, g_lastSl, (u32) g_sock);
        put32(g_tx + 8, g_waitSeq);
        for (u32 i = 0; i < nargs; i++) put32(g_tx + 12 + i * 4, args[i]);
        tx(type, 4 + nargs * 4);
    }
    return 0;
}

static void enter_room(u32 self, u32 gid) {
    g_gid    = gid;
    g_inRoom = 1;
    W(self + 0x4800) = gid;
    W(self + 0x47f4) = 1;
    W(self + 0x4780) = 1;
    W(self + 0x485c) = 1;
    g_lastKeepTick = g_tick;
}

// ---- Replaced game functions --------------------------------------------------------------------------------------

// OnlineWiiUNexSystemWiiU::Process: the original returns before MatchmakeProcess when NEX is not connected
// (always, offline). Run the queued phases, then our network.
s32 lr_Process(u32 self) {
    lr_dbg[0]++;
    g_tick++;
    GFN(LRA_QUEUE_PROCESS, fn_this)(self);
    lr_dbg[5]++;
    poll(self);
    GFN(LRA_NEX_SLEEP, fn_this)(3); // this runs in a loop on the network thread
    return 0;
}

// SendTo(buf, len, &sent, pid): UE3 net driver packets.
s32 lr_SendTo(u32 self, const u8 *buf, s32 len, s32 *sent, u32 pid) {
    if (!g_inRoom || len < 0) return 0;
    if (pid == g_pid) {
        p_lock((void *) (self + 0x149e0));
        GFN(LRA_PKT_ADD, fn_add)(self + 0x14930, (s32) pid, (u32) len, buf, 1);
        p_unlock((void *) (self + 0x149e0));
    } else {
        if (len > 1400) len = 1400;
        put32(g_tx + 8, pid);
        cpy(g_tx + 12, buf, (u32) len);
        tx(T_DATA, 4 + (u32) len);
    }
    *sent = len;
    return 1;
}

// InternalSendParticipantInSession(user, pid (0 = everyone), data, len): room messages.
s32 lr_InternalSend(u32 self, u32 user, u32 pid, const u8 *data, u32 len) {
    (void) user;
    if (!g_inRoom) return 10;
    if (pid == 0 || pid == g_pid) {
        u32 q = W((u32) data + 0x18) == 0 ? 0x149a0 : 0x149bc;
        p_lock((void *) (self + 0x149e0));
        GFN(LRA_PKT_ADD, fn_add)(self + q, (s32) g_pid, len, data, 1);
        p_unlock((void *) (self + 0x149e0));
        if (pid == g_pid) return 0;
    }
    if (len > 1400) return 1;
    put32(g_tx + 8, pid);
    cpy(g_tx + 12, data, len);
    tx(T_DATA, 4 + len);
    return 0;
}

// PhaseCreateMatchmakeSessionStart: the server makes the room and answers our PID and the gathering id.
// No server: a local room (gathering 0x12345), as before, so single player keeps working.
s32 lr_CreateStart(u32 self) {
    u32 sess = W(self + 0x47c4);
    s32 r    = request(self, T_CREATE, R_CREATED, 0, 0, 3 * TICKS_PER_SEC_P);
    if (r == 0) return 0;
    u32 gid = 0x12345;
    if (r > 0 && g_replyLen >= 12) {
        g_pid = get32(g_reply + 4);
        gid   = get32(g_reply + 8);
        W(self + 0x2e8) = g_pid;
    }
    if (sess) W(sess + 0xc8) = gid;
    enter_room(self, gid);
    g_owner = g_pid;
    g_nMem  = 1;
    g_mem[0] = g_pid;
    for (u32 k = 0; k < 17; k++) g_names[0][k] = 0;
    for (u32 i = 1; i < MAX_MEMBERS; i++) g_mem[i] = 0;
    apply_members(self);
    W(self + 0x4840) = 0; // only ourselves: nothing to report
    if (r < 0) g_inRoom = 0; // local room: nothing to send
    return 1;
}

// PhaseFindMatchmakeSessionSstart: room search. Fills the game's own session objects (pool at +0x244) the way
// PhaseFindMatchmakeSessionWait does from NEX's MatchmakeSession list; PhaseFindMatchmakeSessionEnd follows.
// LIST body: seq, pid, n, then n x 14 words: gid, owner, members, missionId, gameMode, attr0..5, min, max, start
s32 lr_FindStart(u32 self) {
    s32 r = request(self, T_FIND, R_LIST, 0, 0, 3 * TICKS_PER_SEC_P);
    if (r == 0) return 0;
    if (r < 0 || g_replyLen < 12) return 1; // nothing found
    g_pid = get32(g_reply + 4);
    W(self + 0x2e8) = g_pid;
    u32 n = get32(g_reply + 8);
    // +0x244 points at the pool TArray {data, num, max} (the original reads **(this+0x244)).
    u32 poolArr = W(self + 0x244), out = W(self + 0x47b8);
    if (!poolArr || !out) return 1;
    u32 pool = W(poolArr), poolN = W(poolArr + 4);
    if (!pool) return 1;
    for (u32 i = 0; i < n && i < poolN && 12 + (i + 1) * 56 <= g_replyLen; i++) {
        const u8 *e = g_reply + 12 + i * 56;
        u32 s = W(pool + i * 4);
        if (!s) break;
        u32 vt = W(s);
        // The session's virtual setters (as PhaseFindMatchmakeSessionWait calls them); each must point into
        // the game's code, else nothing is touched.
        u32 ok = vt != 0;
        static const u16 slots[6] = {0x24c, 0x25c, 0x264, 0x26c, 0x274, 0x27c};
        for (u32 k = 0; ok && k < 6; k++) {
            u32 f = W(vt + slots[k]);
            if (f < 0x02000000 + LR_OFF || f >= 0x05000000 + LR_OFF) ok = 0;
        }
        if (!ok) {
            dbg(0x20, s, vt, i);
            break;
        }
        ((fn_v1) (void *) W(vt + 0x24c))(s);                          // Reset
        ((fn_v3) (void *) W(vt + 0x25c))(s, (s32) get32(e + 16), 1); // game mode
        for (u32 a = 0; a < 6; a++) ((fn_v4) (void *) W(vt + 0x264))(s, (s32) a, (s32) get32(e + 20 + a * 4), 1);
        ((fn_v3) (void *) W(vt + 0x26c))(s, 1, 1);                    // matchmake system type
        ((fn_v3) (void *) W(vt + 0x274))(s, (s32) get32(e + 44), 1); // min participants
        ((fn_v3) (void *) W(vt + 0x27c))(s, (s32) get32(e + 48), 1); // max participants
        W(s + 0xa4) = get32(e + 12);                                  // application buffer = mission id
        W(s + 0x90) = get32(e + 52);                                  // start time
        W(s + 0xb8) = get32(e + 8);                                   // participant count
        W(s + 0xc8) = get32(e + 0);                                   // gathering id (= Snow roomId)
        // out->Add(s)
        u32 num = W(out + 4), max = W(out + 8);
        if (num + 1 > max) {
            max = num + 8;
            W(out) = GFN(LRA_APP_REALLOC, fn_realloc)(W(out), max * 4, 8);
            W(out + 8) = max;
        }
        W(W(out) + num * 4) = s;
        W(out + 4) = num + 1;
    }
    return 1;
}

// PhaseLoginMatchmakeSessionStart: join gathering +0x47cc. JOINED body: seq, pid, result, then MEMBERS layout.
s32 lr_LoginStart(u32 self) {
    u32 ctx = W(self + 0x250);
    if (!g_waitType && GFN(LRA_GET_RESULT, fn_getres)(ctx) != 0) return 1;
    u32 gid = W(self + 0x47cc);
    s32 r   = request(self, T_JOIN, R_JOINED, &gid, 1, 5 * TICKS_PER_SEC_P);
    if (r == 0) return 0;
    if (r < 0 || g_replyLen < 12 + 12 || get32(g_reply + 8) != 0) {
        dbg(0x10, gid, (u32) r, g_replyLen >= 12 ? get32(g_reply + 8) : 0xffffffff);
        GFN(LRA_SET_RESULT, fn_setres)(ctx, 1);
        return 1;
    }
    g_pid = get32(g_reply + 4);
    W(self + 0x2e8) = g_pid;
    enter_room(self, gid);
    read_members(g_reply + 12, g_replyLen - 12);
    apply_members(self);
    dbg(0x11, gid, g_owner, g_nMem);
    return 1;
}

// LogoutMatchmakeSession(ctx, gid): leaving or disbanding a room, end of a mission.
s32 lr_Logout(u32 self, u32 ctx, u32 gid) {
    (void) gid;
    if (!ctx) return 7;
    if (g_inRoom) tx1(T_LEAVE, g_gid);
    g_inRoom = 0;
    g_nMem   = 0;
    for (u32 i = 0; i < MAX_MEMBERS; i++) g_mem[i] = 0;
    apply_members(self);
    W(ctx + 0x48)    = 0;
    W(self + 0x47f4) = 0;
    W(self + 0x4780) = 0;
    W(self + 0x485c) = 0;
    W(self + 0x4800) = 0;
    W(self + 0x4784) = 0xffffffff;
    g_gid = 0;
    return 0;
}

// PhaseUpdateMatchmakeSessionAttributeStart: the host changed the room's mission (Snow flow 32). The original sends
// NEX UpdateMatchmakeSessionAttribute (session +0xc8 gathering id, +0x48 the 6 attributes) and fails offline.
// Tell the relay instead (UPDATE gid missionId attr0..5); PhaseUpdateMatchmakeSessionEnd follows.
s32 lr_UpdateAttrStart(u32 self) {
    u32 ctx = W(self + 0x250);
    if (GFN(LRA_GET_RESULT, fn_getres)(ctx) != 0) return 1;
    u32 sess = W(self + 0x47c8);
    if (g_inRoom && sess) {
        put32(g_tx + 8, g_gid);
        put32(g_tx + 12, W(sess + 0xa4)); // application value = mission id
        for (u32 a = 0; a < 6; a++) put32(g_tx + 16 + a * 4, W(sess + 0x48 + a * 4));
        tx(T_UPDATE, 32);
    }
    return 1;
}

// PhaseOpenParticipatStart / PhaseCloseParticipatStart: room open to joiners or closed (mission starting).
s32 lr_OpenStart(u32 self) {
    (void) self;
    if (g_inRoom) tx2(T_OPEN, g_gid, 1);
    return 1;
}
s32 lr_CloseStart(u32 self) {
    (void) self;
    if (g_inRoom) tx2(T_OPEN, g_gid, 0);
    return 1;
}
