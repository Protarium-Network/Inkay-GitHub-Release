#pragma once

// FIFA 13 (Wii U, update): the redirector connection of the Blaze SDK is forced to plain TCP (like nfs_online.cpp) so it
// can reach the Protarium Python Blaze server on 42127. Called from WUMS_ALL_APPLICATION_STARTS_DONE.
void patch_fifa_online();
