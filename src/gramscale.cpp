// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gramscale.h>

#include <univalue.h>

#include <tinyformat.h>

// Launch presentation scale; regtest may override via -launchsatspergram.
int64_t g_launchSatsPerGram = DEFAULT_LAUNCH_SATS_PER_GRAM;

double GramsFromSats(int64_t sats)
{
    if (g_launchSatsPerGram <= 0)
        return 0.0;
    return (double)sats / (double)g_launchSatsPerGram;
}

UniValue GramsUV(int64_t sats)
{
    return UniValue(UniValue::VNUM, strprintf("%.6f", GramsFromSats(sats)));
}
