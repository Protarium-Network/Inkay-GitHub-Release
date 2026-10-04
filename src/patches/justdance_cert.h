#pragma once

// Just Dance 2017 (Wii U) ships its own static OpenSSL 1.0.2 + libcurl inside
// wiiu_ua_engine_f.rpx. It verifies the UbiServices/JMCS server cert against a
// bundled CA store, so a MITM cert is rejected during the TLS handshake
// (alert 45/48) - the console-level NoSSL patch does not cover it. This neuters
// ssl_verify_cert_chain() in the loaded RPX so the handshake completes.
void patch_justdance_cert();
