// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NOTE_H
#define BITCOIN_NOTE_H

#include <amount.h>
#include <house.h>            // AttestProof (the rho-at-mint reserve proof, R-i7)
#include <pubkey.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <string>
#include <vector>

class CValidationState;

//
// Notes (Phase 3.2) - the per-house named credit asset.
//
// A note is a CREDIT CLAIM, not a locked coin. A house mints up to lambda*E
// note-units against E escrow (CM-2; lambda up to 3x), so notes are NOT
// 100%-reserved - they cannot be modelled as colored sats (that would force a
// full reserve and defeat fractional credit). Instead each note UTXO carries
// its claim `nNoteUnits` as a SEPARATE coin field and holds only a dust
// base-value; minting creates claims (tracked in CHouse.nMintedUnits), never
// base-coin, and redemption pays real base-coin from the house's own reserves.
// Structurally this is the Bills model (dust UTXO + separate amount) made
// fungible and divisible.
//
// v1 is base-native 1:1 (1 note-unit redeems for 1 base-sat); the house's
// gold-unit denomination fields ride inert (the D14 oracle migration). Full
// transparency; holder identity = pubkey pseudonym.
//
// All constants PROVISIONAL (N-1) - revisit before real value.
//

// Note operations carried by TRANSACTION_NOTE_VERSION transactions
static const uint8_t NOTE_OP_MINT     = 1;
static const uint8_t NOTE_OP_TRANSFER = 2;
static const uint8_t NOTE_OP_REDEEM   = 3;
// Reserved INERT for the v1.5 Chaumian bearer layer (D8). Rejected in v1 shape
// (unreachable) so the op-codes are permanently claimed without behaviour.
static const uint8_t NOTE_OP_LOCK     = 4;
static const uint8_t NOTE_OP_UNLOCK   = 5;
// Phase 3.4 insolvency waterfall: holder claims pro-rata from the escrow pot
static const uint8_t NOTE_OP_CLAIM    = 6;
// Phase 3.5 option clause: the holder LODGES A DEMAND while the house is
// suspended, which starts their interest clock (5%/yr from the date of demand).
static const uint8_t NOTE_OP_DEMAND   = 7;

// Dust base-value each note UTXO carries (it holds the claim, not value).
static const CAmount NOTE_DUST_VALUE = 1000;

// Max note outputs per MINT/TRANSFER (bounds payload + per-tx loops). PROVISIONAL (N-1).
static const size_t MAX_NOTE_OUTPUTS = 100;

/** MINT: a house mints note-units to holders. vout[0..vUnits.size()-1] are the
 * new note coins (P2PKH to holders), each carrying vUnits[i] claim units and
 * NOTE_DUST_VALUE sats (funded by the house). Approved by the house M-of-N over
 * the mint sighash (house_id + vUnits + hashOutputs). Cap:
 * nMintedUnits + sum(vUnits) <= (HOUSE_LAMBDA_X10[tier]/10) * ActiveEscrow(). */
struct NoteMint {
    uint32_t nHouseID;
    std::vector<uint64_t> vUnits;                         // parallel to the note outputs
    // R-i7 rho-at-mint LIVENESS gate (DR-1): the mint proves its liquid reserves
    // are still unspent AT MINT TIME, rather than the cap trusting a stored
    // attestation snapshot the house could have spent. Same proof primitive as
    // HOUSE_OP_ATTEST: declared outpoints + per-coin sigs over a recency
    // challenge at nAsOfHeight. The reserve cap uses the freshly-proven sum.
    uint32_t nAsOfHeight;
    std::vector<AttestProof> vReserveProofs;              // <= MAX_ATTEST_PROOFS
    std::vector<uint32_t> vApproverIndex;                 // strictly ascending
    std::vector<std::vector<unsigned char>> vApproverSig;

    NoteMint() : nHouseID(0), nAsOfHeight(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(vUnits);
        READWRITE(nAsOfHeight);
        READWRITE(vReserveProofs);
        READWRITE(vApproverIndex);
        READWRITE(vApproverSig);
    }
};

/** TRANSFER: the current holder (single sender, v1) spends note coin(s) of one
 * house and re-issues note coin(s) to new holders at vout[0..vUnits.size()-1].
 * Conserves sum(in units) == sum(vUnits). Authorized by the sender's signature
 * over (house_id + vUnits + hashOutputs) - which is what binds the trailer
 * payload the legacy input sighash does NOT cover. */
struct NoteTransfer {
    uint32_t nHouseID;
    std::vector<uint64_t> vUnits;                         // parallel to the note outputs
    // The demand height carried by the notes being moved (0 = undemanded).
    // A DEMANDED note stays TRANSFERABLE and keeps its clock: consensus
    // requires every spent note input to carry exactly this height, and tags
    // the new outputs with it. That is what gives a queued holder a secondary
    // exit - sell at a market discount - rather than being trapped for the
    // whole window, and it is the only thing the record says legitimises a
    // private suspension (a suspension AT PAR is what it calls the crime).
    uint32_t nDemandHeight;
    std::vector<unsigned char> vchSenderPubKey;           // must hash to every spent note input
    std::vector<unsigned char> vchSenderSig;

    NoteTransfer() : nHouseID(0), nDemandHeight(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(vUnits);
        READWRITE(nDemandHeight);
        READWRITE(vchSenderPubKey);
        READWRITE(vchSenderSig);
    }
};

/** DEMAND (Phase 3.5, ARCH s7 Option (c) step 2): while the house is suspended,
 * the holder presents their notes for payment. The notes are NOT surrendered -
 * they are re-issued to the same holder, now stamped with the demand height, so
 * interest runs from the date of demand (the historical rule: "5% per annum
 * from the date of demand"). Valid ONLY at effective Deferred: while the house
 * is Open or Stressed the holder simply REDEEMS at par, and once Insolvent the
 * pro-rata waterfall replaces redemption entirely. Changes no house state -
 * outstanding units are unchanged (a demanded note is still a liability, and if
 * it left nMintedUnits the wind-down and escrow-reclaim gates would open under
 * the queued holders' feet). */
struct NoteDemand {
    uint32_t nHouseID;
    std::vector<uint64_t> vUnits;                         // parallel to the re-issued note outputs
    std::vector<unsigned char> vchHolderPubKey;           // must hash to every spent note input
    std::vector<unsigned char> vchHolderSig;

    NoteDemand() : nHouseID(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(vUnits);
        READWRITE(vchHolderPubKey);
        READWRITE(vchHolderSig);
    }
};

/** REDEEM: the holder burns note coin(s) of one house (U units total) and is
 * paid base-coin. Holder protection is by SIGNATURE, not a consensus payout
 * floor: the holder signs (house_id + U + hashOutputs) AND supplies the P2PKH
 * scriptSig for every burned note input (SIGHASH_ALL) - both bind the exact
 * output set, so the holder never surrenders notes without endorsing the payout
 * they receive. The house funds the payout from its own key-signed base-coin
 * inputs. Consensus does NOT enforce a >= U floor (D5). nMintedUnits -= U. */
struct NoteRedeem {
    uint32_t nHouseID;
    // 1 -> vout[1] is the DYNAMIC BRASSAGE output: the redemption spread, paid
    // into the house's escrow pot (3.5 D1/D10). Required whenever the house's
    // attested ratio is below rho; forbidden when the spread is zero (an
    // untracked escrow-script output would enter the UTXO set anyone-can-spend).
    uint8_t fBrassage;
    std::vector<unsigned char> vchHolderPubKey;           // must hash to every spent note input; receives the payout
    std::vector<unsigned char> vchHolderSig;

    NoteRedeem() : nHouseID(0), fBrassage(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(fBrassage);
        READWRITE(vchHolderPubKey);
        READWRITE(vchHolderSig);
    }
};

/** CLAIM (Phase 3.4, ARCH s7 Option a-2): at effective-Insolvent, the holder
 * burns note coin(s) of the house (U units) and takes AT MOST the pro-rata
 * entitlement min(U, U*pot/units) from the house's escrow coins - pot and
 * units are the FIXED snapshot written by the first claim (order-independent,
 * no front-running; D5/D15: claims never expire, holders senior forever).
 * vin = holder's note coins + house escrow coins + plain fee coins;
 * vout[0] = payout (the holder signs the exact output set); if fEscrowChange,
 * vout[1] returns escrow change to the canonical escrow script (re-tagged
 * from this self-contained payload - AddCoins/mempool/rollforward identical). */
struct NoteClaim {
    uint32_t nHouseID;                                    // leading - guard convention
    uint8_t fEscrowChange;                                // 1 -> vout[1] is escrow change
    std::vector<unsigned char> vchHolderPubKey;           // must hash to every spent note input
    std::vector<unsigned char> vchHolderSig;

    NoteClaim() : nHouseID(0), fEscrowChange(0) {}

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
// Pure helpers (note.cpp)
//

/** Note UTXO lock: standard P2PKH to the holder. Note-ness is carried by the
 * coin tag (fNote + nHouseID + nNoteUnits), never the script - so a transfer is
 * an ordinary key-spend and the tag propagates via the v13 op (Bills pattern). */
CScript NoteScriptForPubKey(const std::vector<unsigned char>& vchPubKey);

/** SHA256d over every input outpoint of tx - the tx-unique element bound into
 * the mint sighash so reused M-of-N approver signatures cannot authorize a
 * second, differently-funded mint (MINT spends only fungible plain inputs, so
 * without this its authorization is replayable). */
uint256 NoteHashPrevouts(const CTransaction& tx);

uint256 NoteMintSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits, const uint256& hashPrevouts, const uint256& hashOutputs);
uint256 NoteTransferSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits, const uint256& hashOutputs);
uint256 NoteRedeemSigHash(uint32_t nHouseID, uint64_t nUnitsBurned, const uint256& hashOutputs);
uint256 NoteClaimSigHash(uint32_t nHouseID, uint64_t nUnitsBurned, const uint256& hashOutputs);
uint256 NoteDemandSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits, const uint256& hashOutputs);

/** Deferral interest (Phase 3.5 D6): nUnits held demanded for nBlocks, at
 * HOUSE_DEFER_INTEREST_BPS per year, pro-rated by block. Simple (not
 * compounding) - the Scottish clause was 5% flat. 128-bit intermediate:
 * nUnits <= 3*MAX_MONEY and nBlocks is unbounded in principle, so the product
 * overflows uint64. Returns the INTEREST only, not principal + interest. */
CAmount NoteDeferralInterest(uint64_t nUnits, uint32_t nBlocks);

/** The pro-rata waterfall entitlement: burning nUnits against the insolvency
 * snapshot (amountPot escrow backing nSnapshotUnits claims) entitles the
 * holder to min(nUnits, floor(nUnits * amountPot / nSnapshotUnits)) sats.
 * 128-bit intermediate (the product overflows uint64). Returns 0 if
 * nSnapshotUnits == 0. */
CAmount NoteClaimEntitlement(uint64_t nUnits, const CAmount& amountPot, uint64_t nSnapshotUnits);

/** A partner's residual share at whole-house settlement: distributes
 * amountResidual pro-rata by pledge over amountPledgeSum. 128-bit; 0 if the
 * pledge sum is 0. Sum over partners never exceeds amountResidual. */
CAmount HouseResidualShare(const CAmount& amountPledge, const CAmount& amountResidual, const CAmount& amountPledgeSum);

/** Sum a vUnits vector with overflow protection (returns false on overflow or
 * a zero total / any zero element). */
bool SumNoteUnits(const std::vector<uint64_t>& vUnits, uint64_t& total);

template <typename T>
bool DecodeNotePayload(const std::vector<unsigned char>& vch, T& payload);

/** Context-free shape rules for v13 note txs (no DB, no ECDSA - signatures and
 * the cap/status checks run contextually in CheckNoteOperation, DoS pricing). */
bool CheckNoteTransactionShape(const CTransaction& tx, CValidationState& state);

#endif // BITCOIN_NOTE_H
