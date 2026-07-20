// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AMOUNT_H
#define BITCOIN_AMOUNT_H

#include <stdint.h>

/** Amount in satoshis (Can be negative) */
typedef int64_t CAmount;

static const CAmount COIN = 100000000;
static const CAmount CENT = 1000000;

/** Launch presentation scale: satoshis per gram of gold. PRESENTATION ONLY - a
 *  launch-price scale for showing the base unit in grams of gold. It is NOT
 *  consensus-enforced and has no serialization / tx / DB impact (a restart
 *  needs no -reindex). Redemption remains fixed at par in ECX.
 *
 *  Derivation (USD deliberately kept OUT of the code - only the ratio is
 *  stored): launch guess ECX $3000, gold $4500/oz => $144.678/g =>
 *  0.0482261 ECX/g => 4,822,613 sats/g (1 ECX = 1e8 sats). Frozen launch
 *  scale. Regtest may override the runtime value via -launchsatspergram; see
 *  g_launchSatsPerGram / GramsFromSats in gramscale.h. */
static const int64_t DEFAULT_LAUNCH_SATS_PER_GRAM = 4822613;

/** No amount larger than this (in satoshi) is valid.
 *
 * Note that this constant is *not* the total money supply, which in Bitcoin
 * currently happens to be less than 21,000,000 BTC for various reasons, but
 * rather a sanity check. As this sanity check is used by consensus-critical
 * validation code, the exact value of the MAX_MONEY constant is consensus
 * critical; in unusual circumstances like a(nother) overflow bug that allowed
 * for the creation of coins out of thin air modification could lead to a fork.
 * */
static const CAmount MAX_MONEY = 21000000 * COIN;
inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

#endif //  BITCOIN_AMOUNT_H
