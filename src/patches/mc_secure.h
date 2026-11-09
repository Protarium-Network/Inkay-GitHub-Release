#pragma once

// Minecraft: Wii U Edition (Minecraft.Client.rpx, update v688): NOPs out 3 bctrl calls and turns a
// conditional branch into an unconditional one at the client-side anti-cheat validation site, so the
// check always takes the "passed" path on the Protarium server. Called from WUMS_ALL_APPLICATION_STARTS_DONE.
void patch_mc_secure();