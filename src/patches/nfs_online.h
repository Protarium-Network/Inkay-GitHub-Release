#pragma once

// Need for Speed Most Wanted U (Hawaii, update v32): makes the game's Blaze "is this user logged in?" check
// succeed on the Protarium server. Called from WUMS_ALL_APPLICATION_STARTS_DONE.
void patch_nfs_online();
