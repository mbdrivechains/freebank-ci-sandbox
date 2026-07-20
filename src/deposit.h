// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPOSIT_H
#define BITCOIN_DEPOSIT_H

#include <amount.h>
#include <pubkey.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <string>
#include <vector>

class CValidationState;

//
// Term deposits (Phase 3.8, SO-1c) - the Scottish funding flywheel.
//
// A deposit is a TERM-LOCKED, NON-REDEEMABLE-EARLY, TRANSFERABLE receipt: the
// saver lends the house `principal` at a house-set `rate` until `maturity`, and
// takes principal + accrued interest at maturity. There is NO run channel - the
// house never redeems a live receipt; early liquidity is a market sale of the
// receipt (the AMM prices it). Deposits are the D in the CM-2 cap N + D <= lambda
// * E (a liability sharing the notes' leverage ceiling), sit OUTSIDE the rho /
// demand-coverage liquidity machinery (a term-locked claim cannot run), and are
// JUNIOR to notes in the failure waterfall (loss order escrow -> deposits ->
// notes; notes senior). Receipt-ness rides the coin TAG (fDeposit + terms), never
// the script - like notes/bills.
//
// v1 is base-native 1:1 (principal is literally base sats; the ECX/gold
// denomination distinction the canon markets does not physically exist until the
// D14 oracle migration). Whole-receipt atomic transfers (divisibility via batch
// origination). Mint-model funding (ORIGINATE authorizes the liability + emits
// the receipt; the saver->house payment is built in-tx by the wallet but is not a
// consensus invariant, exactly as NoteMint does not verify a note holder paid).
//
// All constants PROVISIONAL (D-1) - revisit before real value.
//

// Deposit operations carried by TRANSACTION_DEPOSIT_VERSION transactions
static const uint8_t DEPOSIT_OP_ORIGINATE = 1;   // house issues receipt(s) (batch)
static const uint8_t DEPOSIT_OP_TRANSFER  = 2;   // holder reassigns a whole receipt
static const uint8_t DEPOSIT_OP_WITHDRAW  = 3;   // holder takes principal + accrued at maturity (Open)
static const uint8_t DEPOSIT_OP_CLAIM     = 4;   // holder takes the subordinated pro-rata at Insolvent

// Dust base-value each receipt UTXO carries (it holds the claim, not value).
static const CAmount DEPOSIT_DUST_VALUE = 1000;

// Max receipts originated per ORIGINATE tx (bounds payload + per-tx loops).
static const size_t MAX_DEPOSIT_OUTPUTS = 100;

// Max term (blocks) a receipt may run: bounds the 128-bit weighted-maturity
// accumulator magnitude and rejects absurd maturities. ~50 years at 10-min
// blocks. PROVISIONAL (D-1).
static const uint32_t MAX_DEPOSIT_TERM_BLOCKS = 2628000;

/** ORIGINATE: a house issues a BATCH of term-deposit receipts. vout[0..n-1] are
 * the receipt coins (P2PKH to savers), each carrying (vPrincipal[i], vRateBps[i],
 * vMaturityHeight[i], origination = this block's height) and DEPOSIT_DUST_VALUE
 * sats. A batch is how divisibility is achieved (transfers are whole-receipt).
 * Approved by the house M-of-N over the ORIGINATE sighash, which binds
 * hashPrevouts (ORIGINATE spends only fungible plain inputs, so without it the
 * approval is replayable with fresh funding - the notes-MINT lesson). Cap:
 * N + D + sum(vPrincipal) <= (lambda/10) * ActiveEscrow(). */
struct DepositOriginate {
    uint32_t nHouseID;                                    // LEADING (mempool one-op guard memcpys first 4 bytes)
    std::vector<uint64_t> vPrincipal;                     // parallel to the receipt outputs
    std::vector<uint32_t> vRateBps;                       // per-receipt annual rate (house-set)
    std::vector<uint32_t> vMaturityHeight;                // per-receipt term-lock end
    std::vector<uint32_t> vApproverIndex;                 // strictly ascending
    std::vector<std::vector<unsigned char>> vApproverSig;

    DepositOriginate() : nHouseID(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(vPrincipal);
        READWRITE(vRateBps);
        READWRITE(vMaturityHeight);
        READWRITE(vApproverIndex);
        READWRITE(vApproverSig);
    }
};

/** TRANSFER: the holder reassigns ONE whole receipt to a new holder. The
 * immutable terms are carried in the payload and MUST equal the spent receipt's
 * coin-tag fields byte-exact (no re-pricing); the new output is tagged
 * identically to the new holder. Authorized by the sender's signature over
 * (house_id + terms + hashOutputs). Changes NO house state (the liability is
 * unchanged - only its bearer moves), so it does not take the house's per-block
 * op slot and is unlimited per block. */
struct DepositTransfer {
    uint32_t nHouseID;
    uint64_t nPrincipal;
    uint32_t nRateBps;
    uint32_t nMaturityHeight;
    uint32_t nOriginationHeight;
    std::vector<unsigned char> vchSenderPubKey;           // must hash to the spent receipt input
    std::vector<unsigned char> vchSenderSig;

    DepositTransfer() : nHouseID(0), nPrincipal(0), nRateBps(0), nMaturityHeight(0), nOriginationHeight(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(nPrincipal);
        READWRITE(nRateBps);
        READWRITE(nMaturityHeight);
        READWRITE(nOriginationHeight);
        READWRITE(vchSenderPubKey);
        READWRITE(vchSenderSig);
    }
};

/** WITHDRAW: at or after maturity AND while the house is effectively Open, the
 * holder burns the receipt and is paid principal + accrued interest. The receipt
 * terms come from the spent coin tag (not the payload). Consensus enforces a
 * FLOOR (unlike note par-redemption's free-choice payout): vout[0] to the holder
 * >= principal + DepositMaturityInterest(principal, payment_height -
 * origination_height, rate) - a matured saver with no leverage must not be forced
 * to sign away accrued. The holder also signs the exact output set (SIGHASH_ALL
 * on the burned receipt input) so cannot be shortchanged. House funds the payout
 * from its own base-coin inputs. nDepositUnits -= principal. */
struct DepositWithdraw {
    uint32_t nHouseID;
    std::vector<unsigned char> vchHolderPubKey;           // must hash to the burned receipt input; receives payout
    std::vector<unsigned char> vchHolderSig;

    DepositWithdraw() : nHouseID(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(vchHolderPubKey);
        READWRITE(vchHolderSig);
    }
};

/** CLAIM: at effective-Insolvent, the holder burns the receipt and takes the
 * SUBORDINATED pro-rata entitlement from the escrow pot - AFTER notes are made
 * whole at par (deposits are junior). The deposit tranche = max(0, pot -
 * note-par-snapshot), and the entitlement is capped at principal (accrued
 * interest does NOT survive materialization, symmetric with notes). Both the
 * tranche and the deposit snapshot are frozen at materialization, so claims are
 * order-independent and provably cannot touch the senior note par tranche.
 * vout[0] = payout (holder signs the exact output set); if fEscrowChange,
 * vout[1] returns escrow change to the canonical escrow script. */
struct DepositClaim {
    uint32_t nHouseID;                                    // leading
    uint8_t fEscrowChange;                                // 1 -> vout[1] is escrow change
    std::vector<unsigned char> vchHolderPubKey;           // must hash to the burned receipt input
    std::vector<unsigned char> vchHolderSig;

    DepositClaim() : nHouseID(0), fEscrowChange(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(fEscrowChange);
        READWRITE(vchHolderPubKey);
        READWRITE(vchHolderSig);
    }
};

//
// Pure helpers (deposit.cpp)
//

/** Receipt UTXO lock: standard P2PKH to the holder. Deposit-ness is carried by
 * the coin tag (fDeposit + terms), never the script - so a transfer is an
 * ordinary key-spend and the tag propagates via the v14 op (notes/bills pattern). */
CScript DepositScriptForPubKey(const std::vector<unsigned char>& vchPubKey);

/** SHA256d over every input outpoint of tx - bound into the ORIGINATE sighash so
 * reused M-of-N approver signatures cannot authorize a second, differently-funded
 * origination. */
uint256 DepositHashPrevouts(const CTransaction& tx);

uint256 DepositOriginateSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vPrincipal,
                                const std::vector<uint32_t>& vRateBps, const std::vector<uint32_t>& vMaturityHeight,
                                const uint256& hashPrevouts, const uint256& hashOutputs);
uint256 DepositTransferSigHash(uint32_t nHouseID, uint64_t nPrincipal, uint32_t nRateBps,
                               uint32_t nMaturityHeight, uint32_t nOriginationHeight, const uint256& hashOutputs);
uint256 DepositWithdrawSigHash(uint32_t nHouseID, uint64_t nPrincipal, uint32_t nMaturityHeight,
                               uint32_t nOriginationHeight, const uint256& hashOutputs);
uint256 DepositClaimSigHash(uint32_t nHouseID, uint64_t nPrincipal, const uint256& hashOutputs);

/** Accrued interest on a matured receipt: principal held nBlocks at rateBps per
 * year, pro-rated by block (simple, not compounding). 128-bit intermediate
 * (principal <= MAX_MONEY times an unbounded block count overflows u64). Returns
 * the INTEREST only, capped at MAX_MONEY. */
CAmount DepositMaturityInterest(uint64_t nPrincipal, uint32_t nBlocks, uint32_t nRateBps);

/** Subordinated pro-rata entitlement at insolvency: burning `nPrincipal` against
 * the frozen deposit tranche (amountDepositPot backing nSnapshotPrincipal of
 * senior-to-partners-but-junior-to-notes claims) entitles the holder to
 * min(nPrincipal, floor(nPrincipal * amountDepositPot / nSnapshotPrincipal)).
 * 128-bit; 0 if nSnapshotPrincipal == 0. */
CAmount DepositClaimEntitlement(uint64_t nPrincipal, const CAmount& amountDepositPot, uint64_t nSnapshotPrincipal);

/** Sum a principal vector with overflow protection (false on overflow or a zero
 * total / any zero element). */
bool SumDepositPrincipal(const std::vector<uint64_t>& vPrincipal, uint64_t& total);

template <typename T>
bool DecodeDepositPayload(const std::vector<unsigned char>& vch, T& payload);

/** Context-free shape rules for v14 deposit txs (no DB, no ECDSA - signatures and
 * the cap/status/maturity checks run contextually in CheckDepositOperation). */
bool CheckDepositTransactionShape(const CTransaction& tx, CValidationState& state);

#endif // BITCOIN_DEPOSIT_H
