// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_GRAMSCALE_H
#define BITCOIN_GRAMSCALE_H

#include <amount.h>

#include <stdint.h>

class UniValue;

// Runtime launch presentation scale, satoshis per gram of gold. Defaults to
// DEFAULT_LAUNCH_SATS_PER_GRAM (amount.h); regtest-only -launchsatspergram
// override set in init.cpp, mirroring the -attestcadence / -deferwindow
// pattern. PRESENTATION ONLY - not consensus, no serialization/tx/DB impact.
extern int64_t g_launchSatsPerGram;

// Grams of gold represented by a base-native amount. Notes are base-native
// (1 note-unit = 1 sat), so grams = sats / g_launchSatsPerGram. Guarded
// against a non-positive scale (returns 0.0).
double GramsFromSats(int64_t sats);

// Shared presentation formatter for gram-of-gold companion fields. Returns a
// 6-decimal numeric UniValue so precision is consistent everywhere. Takes SATS
// (int64/CAmount), NOT a ValueFromAmount decimal. PRESENTATION ONLY.
UniValue GramsUV(int64_t sats);

#endif // BITCOIN_GRAMSCALE_H
