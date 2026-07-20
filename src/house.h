// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HOUSE_H
#define BITCOIN_HOUSE_H

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
// Discount houses (Phase 3.1).
//
// A house is the note-issuing institution of the credit layer: a tiered,
// escrow-bonded registration whose pre-funded pledge capital is the ONLY
// input to the note-issuance cap (CM-2: N + D <= lambda * E; escrow-only
// counting). Four liability tiers ship in v1 (D1): solo bonded/encumbered
// (tiers 0/1, one partner) and multi-partner restricted structures (tier 2 =
// fixed M-of-N set, tier 3 = M-of-N with admission gate). Any partner leaving
// a multi-partner house - exit, expulsion, or house wind-down - has their
// pledge TAIL-LOCKED (Scottish post-exit liability), excluded from cap math
// immediately but reclaimable only after the tail expires.
//
// All constants are PROVISIONAL (H-1 / H-2) - revisit before real value.
//

// House operations carried by TRANSACTION_HOUSE_VERSION transactions
static const uint8_t HOUSE_OP_REGISTER = 1;
static const uint8_t HOUSE_OP_TOPUP    = 2;
static const uint8_t HOUSE_OP_ADMIT    = 3;
static const uint8_t HOUSE_OP_EXIT     = 4;
static const uint8_t HOUSE_OP_WINDDOWN = 5;
static const uint8_t HOUSE_OP_RECLAIM  = 6;
static const uint8_t HOUSE_OP_ATTEST   = 7;  // Phase 3.4 reserve attestation
static const uint8_t HOUSE_OP_DEFER    = 8;  // Phase 3.5 option clause: invoke
static const uint8_t HOUSE_OP_RENEW    = 9;  // Phase 3.5 option clause: one renewal
static const uint8_t HOUSE_OP_RELEASE  = 10; // Phase 3.5: release the locked till after recovery

// On-chain house status. Open / WoundDown are STORED; Stressed, Deferred and
// (until a waterfall op materializes it) Insolvent are DERIVED from stored
// heights by HouseEffectiveStatus - the 3.4 lazy machine, which 3.5 extends
// with the option clause. Deferred is a substate of Stressed: the house is
// impaired AND has invoked the clause, so redemption is queued rather than
// paid at par (ARCH s7 Option (c)).
static const char HOUSE_STATUS_OPEN       = 'o';
static const char HOUSE_STATUS_STRESSED   = 's'; // derived (3.4)
static const char HOUSE_STATUS_DEFERRED   = 'd'; // derived (3.5, option clause)
static const char HOUSE_STATUS_INSOLVENT  = 'i'; // derived, then materialized (3.4 / ARCH s7)
static const char HOUSE_STATUS_WOUNDDOWN  = 'w';

// Partner pledge status
static const char HOUSE_PARTNER_ACTIVE  = 'a';
static const char HOUSE_PARTNER_TAIL    = 't';
static const char HOUSE_PARTNER_SETTLED = 'x'; // residual paid at insolvency settle (3.4)

// Liability tiers (ARCH s6A). Tier semantics v1:
//   0 - bonded solo        (N == 1, M == 1)
//   1 - encumbered solo    (N == 1, M == 1; encumbrance is trust-only, CM-2)
//   2 - restricted M-of-N  (N >= 2, fixed set - no ADMIT)
//   3 - multi-partner      (N >= 2, ADMIT gated by M-of-N co-sign)
static const uint8_t HOUSE_TIER_BONDED_SOLO     = 0;
static const uint8_t HOUSE_TIER_ENCUMBERED_SOLO = 1;
static const uint8_t HOUSE_TIER_RESTRICTED      = 2;
static const uint8_t HOUSE_TIER_MULTI_PARTNER   = 3;
static const uint8_t MAX_HOUSE_TIER             = 3;

// Issuance-cap multiplier per tier, x10 (D4, PROVISIONAL H-1): the 3.2 mint
// cap enforces  notes + deposits <= (lambda_x10 / 10) * escrow.  T3 = 3.0 is
// the sim champion; lower tiers tighten linearly. Declared here so 3.2 / 3.4
// read one table.
static const uint32_t HOUSE_LAMBDA_X10[4] = {10, 15, 20, 30};

// Reserve floor (rho), percent of nMintedUnits the attested liquid till must
// cover. PROVISIONAL (H-1); enforced by the 3.4 attestation. Under D=0 and no
// secondary reserves this is also the CM-7 demand-coverage floor (same check).
static const uint32_t HOUSE_RESERVE_FLOOR_PCT = 10;

// Minimum pledge per partner, sats. PROVISIONAL (H-1).
static const CAmount HOUSE_MIN_PLEDGE = 10000000;

// Partner-set bounds. PROVISIONAL (H-1). (Aberdeen Town & County had 446
// partners in 1820; v1 caps the set to keep register txs and threshold
// verification bounded.)
static const size_t MAX_HOUSE_PARTNERS = 64;

// Pledge outpoints per partner. PROVISIONAL (H-3). Bounds the RECLAIM input
// scan and the on-disk CHouse record size against a top-up flood; a partner
// wanting more backing coalesces into larger top-ups. Enforced at TOPUP.
static const size_t MAX_HOUSE_PLEDGE_OUTPOINTS = 64;

// Tail-liability lock: blocks a leaving partner's pledge stays locked
// (~3 years at 10-minute blocks). PROVISIONAL (H-2); GovernX-mutable later.
static const uint32_t HOUSE_TAIL_BLOCKS = 157680;

// Note-class id: 1..16 chars, [a-z0-9] (ARCH s5, embedded at registration, D3)
static const size_t MAX_HOUSE_CLASS_ID_BYTES = 16;

// Stressed-state recovery window (ARCH s3.4): blocks from the stress origin
// until a house becomes (lazily) Insolvent. PROVISIONAL (H-1). Consensus
// value 1008; mutable ONLY via the regtest-gated -stressedwindow override
// (integration gates cannot mine a week of blocks) - init.cpp rejects the
// arg on any other network.
extern uint32_t HOUSE_STRESSED_WINDOW;

//
// Reserve attestation (Phase 3.4). All PROVISIONAL (A-1); GovernX-mutable
// post-launch. The machine's SHAPE (states, transitions, proof crypto,
// pro-rata formula, note seniority) is consensus-forever; only these dials
// move.
//

// Attestation cadence, blocks (~daily at 10-min target). Consensus value 144;
// regtest-only -attestcadence override (see HOUSE_STRESSED_WINDOW note).
extern uint32_t HOUSE_ATTEST_CADENCE;

// Consecutive missed cadences before a house is (lazily) Stressed. Stress
// origin = nLastAttestHeight + HOUSE_ATTEST_MISS_N * HOUSE_ATTEST_CADENCE + 1.
static const uint32_t HOUSE_ATTEST_MISS_N = 2;

// Max age (blocks) of an attestation's nAsOfHeight at connect time - bounds
// how stale the per-proof block-hash challenge may be (~12 h).
static const uint32_t HOUSE_ATTEST_STALENESS = 72;

// Max reserve-proof outpoints per attestation (mirrors MAX_HOUSE_PLEDGE_OUTPOINTS).
static const size_t MAX_ATTEST_PROOFS = 64;

// Recovery hysteresis: Stressed -> Open requires the attested ratio to reach
// floor + buffer (15%), uniformly for every recovery (D9), so a house cannot
// flap across the 10% boundary. In-band attestations preserve current state.
static const uint32_t HOUSE_RESTORE_BUFFER_PCT = 5;

//
// Option clause (Phase 3.5, ARCH s7 Option (c)). All PROVISIONAL (R-1) and -
// CRITICALLY - none of these numbers is validated for base-native v1: Stage-2's
// calibration was fitted to a payoff geometry we do not have (its failed banks
// repaid ~100c of face; ours repay 1/lambda ~= 33c). The MECHANISM ships; the
// DIALS await a v1-shaped sim run.
//

// Deferral window, blocks (90 days - the only value with survival evidence;
// the 5%/yr rate and the one-renewal rule are calibrated against it).
// Regtest-only -deferwindow override (integration gates cannot mine 90 days).
extern uint32_t HOUSE_DEFER_WINDOW;

// Renewals permitted per deferral episode (sim D2: "one renewal max").
static const uint32_t HOUSE_DEFER_MAX_RENEWALS = 1;

// Deferral interest on demanded notes, basis points per year, accruing from
// the DATE OF DEMAND (the historical rule; Scottish was 5% flat). Consumed by
// R-i3's demand queue.
static const uint32_t HOUSE_DEFER_INTEREST_BPS = 500;
static const uint32_t BLOCKS_PER_YEAR = 52560;

//
// Dynamic brassage (Phase 3.5 D1/D8/D10) - a consensus redemption SPREAD that
// escalates as the attested reserve ratio falls toward theta.
//
// What it is for: the race-to-the-window. Redeeming at par on a fractional
// reserve ALWAYS lowers the reserve ratio (d(rr)/d(delta) = (R-N)/(N-delta)^2 < 0
// for R < N), so each holder who runs makes the next holder's run more urgent.
// The first out gets 100c; those left at insolvency get 1/lambda (33c at T3).
// The spread prices that exit, so the runner compensates the stayers instead of
// stranding them - the fee is a required escrow-tagged output, i.e. it goes
// straight into the pot the stayers will claim from.
//
// theta is a SCHEDULE CONSTANT - the far end of the ramp - NOT a trigger and
// NOT a state. The sim's automatic firing at theta is deliberately rejected: it
// would hand an attacker a kill switch, and it would need a per-height sweep the
// chassis forbids.
//
// !! THE NUMBERS ARE NOT VALIDATED FOR v1 !! Stage-2's calibration was fitted to
// a payoff geometry we do not have (its failed banks repaid ~100c of face; ours
// repay 1/lambda). In the sim's OWN base-native control brassage is a measured
// no-op - its only ignition source is a gold-basis shock that 1:1 removes. The
// MECHANISM ships; these DIALS await a v1-shaped sim run. PROVISIONAL (R-1).
static const uint32_t HOUSE_THETA_BPS = 250;          // rho/4
static const uint32_t HOUSE_BRASSAGE_MAX_BPS = 300;   // 3% at/below theta
// beta_base = 0 (D8a): exact PAR while Open. Since an Open house always has
// rr >= rho (a below-floor attestation is precisely what makes it Stressed),
// the spread can only ever bite once the house is publicly impaired - which
// keeps 3.4-D6's "redemption at par" invariant intact in the Open state at
// zero measured cost.

// Confidence death (sim D15, taken as an INVOCATION GUARD not a kill switch,
// D13): a second activation inside CD_WINDOW, or cumulative suspension beyond
// CD_MAX_SUSPENDED, makes a further DEFER invalid. The house then simply falls
// back to its ordinary stress clock - which is what kills it. No new terminal
// status; the counters are published so the market can price them.
static const uint32_t HOUSE_CD_WINDOW_BLOCKS    = 157680;  // ~36 months
static const uint32_t HOUSE_CD_MAX_SUSPENDED    = 38880;   // ~9 months

// CHouse on-disk serialization version (D10). v4 = 3.5 layout (option-clause
// state). Any record with a different version byte is rejected at read - each
// layout change bumps this and adds a guarded migration.
static const uint8_t HOUSE_SER_VERSION = 6;

/** One partner's pledge. Solo houses (tiers 0/1) hold exactly one entry. */
struct HousePartner {
    std::vector<unsigned char> vchPubKey;  // 33-byte compressed
    CAmount amountPledge;                  // cumulative (register + topups)
    std::vector<COutPoint> vOutPledge;     // the locked escrow UTXO(s)
    char status;                           // active | tail | settled
    uint32_t nTailUnlockHeight;            // valid when status == tail
    // The partner's LIVE escrow at insolvency materialization - their weight
    // in the residual settle (3.4 review). amountPledge is deliberately never
    // decremented by RECLAIM (the 3.1 undo design), so weighting the residual
    // by it would pay a partner who already withdrew their capital, diluting
    // the partners whose escrow is actually in the pot. 0 until materialized.
    CAmount amountInsolventPledge;

    HousePartner() : amountPledge(0), status(HOUSE_PARTNER_ACTIVE), nTailUnlockHeight(0),
                     amountInsolventPledge(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vchPubKey);
        READWRITE(amountPledge);
        READWRITE(vOutPledge);
        READWRITE(status);
        READWRITE(nTailUnlockHeight);
        READWRITE(amountInsolventPledge);
    }
};

/** The consensus house record persisted in HouseDB. */
struct CHouse {
    uint32_t nHouseID;                       // dense id (bill nBillID pattern); coin tags carry this
    uint256 houseID;                         // sha256 of the founding declaration - canonical identity
    uint8_t nTier;
    uint32_t nThresholdM;                    // approvals needed for threshold ops (1 for solo)
    std::vector<HousePartner> vPartner;
    // Note-class declaration (ARCH s5; D3 - embedded at registration)
    std::string strClassID;                  // globally unique, [a-z0-9]{1,16}
    uint64_t nDenomMgGold;                   // smallest unit in mg of gold (CM-4); inert until 3.2
    std::vector<unsigned char> vchRedemptionDestPK;
    char status;
    uint32_t nRegisteredHeight;
    uint256 txidRegister;
    // Outstanding note units (Phase 3.2): the N in the CM-2 cap N + D <= lambda*E
    // and the house's on-chain liability (backs GetHouseLiabilities()). Grown by
    // NOTE_OP_MINT, shrunk by NOTE_OP_REDEEM; reorg-safe via net-delta staging.
    uint64_t nMintedUnits;
    // Reserve attestation state (Phase 3.4). Stressed/Insolvent are DERIVED
    // from these by HouseEffectiveStatus() - status stays 'o' on disk until
    // insolvency is materialized by the first waterfall claim (D3).
    uint32_t nLastAttestHeight;              // init = nRegisteredHeight (one full miss-window of grace)
    CAmount amountLastAttestReserves;        // informational snapshot of the last accepted attestation
    uint32_t nStressSinceHeight;             // 0 = none; ratio-breach stress origin (tx-written by ATTEST)
    // Insolvency snapshot, written once by the first NOTE_OP_CLAIM (stamp-match
    // undo). Fixed denominator for the pro-rata waterfall (D5).
    uint32_t nInsolventHeight;               // 0 = not materialized
    uint64_t nInsolventUnits;                // nMintedUnits at materialization
    CAmount amountInsolventPot;              // total pledged escrow (ACTIVE + TAIL) at materialization
    // Escrow-change outpoints created by waterfall claims (vout[1] of each
    // claim with change): the partner vOutPledge lists keep the ORIGINAL
    // (spent) outpoints, so without this the live pot would be un-enumerable
    // after the first claim. Appended at claim connect, pruned by claim undo.
    std::vector<COutPoint> vOutEscrowChange;
    // Option-clause state (Phase 3.5). Deferral is DERIVED from these, exactly
    // like Stressed/Insolvent - no automatic writes, nothing new to undo.
    uint32_t nDeferInvokedHeight;      // 0 = not deferring; height of the current invocation
    uint32_t nDeferRenewals;           // renewals used on the CURRENT episode (<= MAX_RENEWALS)
    uint32_t nDeferCumBlocks;          // cumulative suspended blocks over CLOSED episodes (CD)
    uint32_t nDeferActivations;        // lifetime invocations (CD)
    uint32_t nDeferLastActivation;     // height of the most recent invocation (CD window)
    // DR-2: the height the most recent deferral episode ENDED (recovery
    // attestation), 0 if none has ever closed. Caps the deferral-interest
    // window on a demanded note - without it the note's nDemandHeight coin tag
    // is forever and the interest clock runs to the eventual redemption,
    // turning "demand once" into a perpetual 5%/yr bond. A note demanded in an
    // EARLIER episode and redeemed after a LATER recovery accrues to the later
    // end (bounded multi-episode over-pay - accepted; per-note episode tracking
    // is not worth the state).
    uint32_t nDeferEndedHeight;
    // The TILL locked into consensus custody at DEFER (3.5 D11). Suspending is
    // not free: a house that stops paying its holders must put its liquid
    // reserves where the holders can reach them. These coins are escrow-tagged,
    // count in the insolvency pot, and are releasable only once the clause has
    // been lifted (HOUSE_OP_RELEASE) - which is what turns 3.4-D12's
    // unenforceable "reserves frozen on first detection" into a real rule, and
    // collapses the run-payoff cliff from 1/lambda toward 1/lambda + rho.
    std::vector<COutPoint> vOutReserveLock;
    // Term-deposit accounting (Phase 3.8). nDepositUnits = the D in the CM-2 cap
    // N + D <= lambda*E: sum of outstanding deposit PRINCIPAL (a liability, grown
    // by ORIGINATE, shrunk by WITHDRAW/CLAIM). nDepositWtMat{Hi,Lo} = the 128-bit
    // Sigma(principal_i * maturity_height_i) accumulator (one term overflows u64:
    // principal <= MAX_MONEY times a height >= 2^76), for the match-funding WAM;
    // stored as two u64 words. nInsolventDepositPrincipal = the waterfall snapshot
    // (0 until the first waterfall op materializes insolvency).
    uint64_t nDepositUnits;
    uint64_t nDepositWtMatHi;
    uint64_t nDepositWtMatLo;
    uint64_t nInsolventDepositPrincipal;

    CHouse() : nHouseID(0), nTier(0), nThresholdM(1), nDenomMgGold(0),
               status(HOUSE_STATUS_OPEN), nRegisteredHeight(0), nMintedUnits(0),
               nLastAttestHeight(0), amountLastAttestReserves(0), nStressSinceHeight(0),
               nInsolventHeight(0), nInsolventUnits(0), amountInsolventPot(0),
               nDeferInvokedHeight(0), nDeferRenewals(0), nDeferCumBlocks(0),
               nDeferActivations(0), nDeferLastActivation(0), nDeferEndedHeight(0),
               nDepositUnits(0), nDepositWtMatHi(0), nDepositWtMatLo(0),
               nInsolventDepositPrincipal(0) {}

    /** The 128-bit weighted-maturity accumulator Sigma(principal_i * maturity_i). */
    unsigned __int128 DepositWtMaturity() const
    {
        return ((unsigned __int128)nDepositWtMatHi << 64) | (unsigned __int128)nDepositWtMatLo;
    }
    void SetDepositWtMaturity(unsigned __int128 v)
    {
        nDepositWtMatHi = (uint64_t)(v >> 64);
        nDepositWtMatLo = (uint64_t)v;
    }

    /** Cap escrow E (CM-2): the sum of ACTIVE pledges only. */
    CAmount ActiveEscrow() const
    {
        CAmount total = 0;
        for (const HousePartner& p : vPartner) {
            if (p.status == HOUSE_PARTNER_ACTIVE)
                total += p.amountPledge;
        }
        return total;
    }

    int ActivePartnerCount() const
    {
        int n = 0;
        for (const HousePartner& p : vPartner) {
            if (p.status == HOUSE_PARTNER_ACTIVE)
                n++;
        }
        return n;
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        // Version prefix (D10): one byte buys guarded migrations for every
        // future layout change. Unknown versions are a hard read failure -
        // never silently defaulted (consensus state).
        uint8_t nSerVersion = HOUSE_SER_VERSION;
        READWRITE(nSerVersion);
        // Guarded migration: a FUTURE version is a hard read failure (never
        // silently defaulted - this is consensus state), but a PAST version is
        // read at its old layout and the fields added since default to their
        // constructor values (below). v4 (pre-3.8) records carry no deposit leg.
        if (ser_action.ForRead() && nSerVersion > HOUSE_SER_VERSION)
            throw std::ios_base::failure("CHouse: unknown serialization version");
        READWRITE(nHouseID);
        READWRITE(houseID);
        READWRITE(nTier);
        READWRITE(nThresholdM);
        READWRITE(vPartner);
        READWRITE(strClassID);
        READWRITE(nDenomMgGold);
        READWRITE(vchRedemptionDestPK);
        READWRITE(status);
        READWRITE(nRegisteredHeight);
        READWRITE(txidRegister);
        READWRITE(nMintedUnits);
        READWRITE(nLastAttestHeight);
        READWRITE(amountLastAttestReserves);
        READWRITE(nStressSinceHeight);
        READWRITE(nInsolventHeight);
        READWRITE(nInsolventUnits);
        READWRITE(amountInsolventPot);
        READWRITE(vOutEscrowChange);
        READWRITE(nDeferInvokedHeight);
        READWRITE(nDeferRenewals);
        READWRITE(nDeferCumBlocks);
        READWRITE(nDeferActivations);
        READWRITE(nDeferLastActivation);
        READWRITE(vOutReserveLock);
        // v5 (Phase 3.8): term-deposit accounting. A v4 record has none of these
        // - they stay 0 from the constructor (a house with no deposits).
        if (nSerVersion >= 5) {
            READWRITE(nDepositUnits);
            READWRITE(nDepositWtMatHi);
            READWRITE(nDepositWtMatLo);
            READWRITE(nInsolventDepositPrincipal);
        }
        // v6 (DR-2): episode-end height for the deferral-interest cap. A v5
        // record defaults to 0 = no episode has closed; a demanded note on such
        // a record keeps the (old) uncapped accrual until the next recovery.
        if (nSerVersion >= 6) {
            READWRITE(nDeferEndedHeight);
        }
    }

    /** The height at which the current deferral episode expires (0 if the house
     * is not deferring). One renewal extends it by a second full window. */
    uint32_t DeferEndHeight() const
    {
        if (nDeferInvokedHeight == 0)
            return 0;
        return nDeferInvokedHeight + HOUSE_DEFER_WINDOW * (1 + nDeferRenewals);
    }

    /** Cumulative suspended blocks INCLUDING the episode running at nHeight -
     * the quantity confidence-death is measured on. */
    uint32_t DeferSuspendedBlocks(int nHeight) const
    {
        uint32_t n = nDeferCumBlocks;
        if (nDeferInvokedHeight != 0 && nHeight > 0 && (uint32_t)nHeight > nDeferInvokedHeight)
            n += (uint32_t)nHeight - nDeferInvokedHeight;
        return n;
    }
};

//
// v12 trailer payloads, one per HOUSE_OP_*
//

/** Founding declaration + one pledge output per partner (vout[i] for partner i).
 * Every founding partner signs HouseRegisterSigHash over the declaration digest
 * + their own index + pledge amount (binds the posted bond - Bills-ISSUE
 * anti-front-run pattern). */
struct HouseRegister {
    uint8_t nTier;
    uint32_t nThresholdM;
    std::string strClassID;
    uint64_t nDenomMgGold;
    std::vector<unsigned char> vchRedemptionDestPK;
    std::vector<std::vector<unsigned char>> vPartnerPubKey;
    std::vector<CAmount> vPledgeAmount;              // parallel to vPartnerPubKey
    std::vector<std::vector<unsigned char>> vPartnerSig;

    HouseRegister() : nTier(0), nThresholdM(1), nDenomMgGold(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nTier);
        READWRITE(nThresholdM);
        READWRITE(strClassID);
        READWRITE(nDenomMgGold);
        READWRITE(vchRedemptionDestPK);
        READWRITE(vPartnerPubKey);
        READWRITE(vPledgeAmount);
        READWRITE(vPartnerSig);
    }
};

/** Partner grows their own pledge; vout[0] = the added escrow output. */
struct HouseTopup {
    uint32_t nHouseID;
    uint32_t nPartnerIndex;
    std::vector<unsigned char> vchSig;   // over HouseTopupSigHash (binds outputs)

    HouseTopup() : nHouseID(0), nPartnerIndex(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(nPartnerIndex);
        READWRITE(vchSig);
    }
};

/** Tier-3 only: add a partner. vout[0] = the new partner's pledge output.
 * New partner signs (binds own key + pledge); M current ACTIVE partners
 * co-sign the same digest. */
struct HouseAdmit {
    uint32_t nHouseID;
    std::vector<unsigned char> vchNewPubKey;
    std::vector<unsigned char> vchNewSig;
    std::vector<uint32_t> vApproverIndex;            // strictly ascending
    std::vector<std::vector<unsigned char>> vApproverSig;

    HouseAdmit() : nHouseID(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(vchNewPubKey);
        READWRITE(vchNewSig);
        READWRITE(vApproverIndex);
        READWRITE(vApproverSig);
    }
};

/** Partner leaves (voluntary: own sig; expulsion: M-of-N approver sigs; either
 * authorization suffices). Pledge -> tail. Rejected if the house would drop
 * below nThresholdM active partners (wind down instead). */
struct HouseExit {
    uint32_t nHouseID;
    uint32_t nPartnerIndex;
    std::vector<unsigned char> vchPartnerSig;        // may be empty (expulsion)
    std::vector<uint32_t> vApproverIndex;            // may be empty (voluntary)
    std::vector<std::vector<unsigned char>> vApproverSig;

    HouseExit() : nHouseID(0), nPartnerIndex(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(nPartnerIndex);
        READWRITE(vchPartnerSig);
        READWRITE(vApproverIndex);
        READWRITE(vApproverSig);
    }
};

/** Voluntary close (M-of-N; solo = the one partner). Consensus requires house
 * liabilities == 0 (trivially true until notes/deposits exist). Multi-partner:
 * every ACTIVE pledge -> tail (height + HOUSE_TAIL_BLOCKS). Solo: pledge ->
 * tail with immediate unlock (no tail, ARCH s3.4). */
struct HouseWinddown {
    uint32_t nHouseID;
    std::vector<uint32_t> vApproverIndex;
    std::vector<std::vector<unsigned char>> vApproverSig;

    HouseWinddown() : nHouseID(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(vApproverIndex);
        READWRITE(vApproverSig);
    }
};

/** One reserve-proof entry of an attestation: an outpoint the house claims as
 * liquid till, the single key that owns it (P2PKH / P2WPKH only in v1), and
 * that key's signature over HouseAttestChallenge(...) - a recent-block-hash
 * challenge proving the coin is spendable NOW (ARCH s6 check 2). */
struct AttestProof {
    COutPoint outpoint;
    std::vector<unsigned char> vchPubKey;  // 33-byte compressed
    std::vector<unsigned char> vchSig;

    AttestProof() {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(outpoint);
        READWRITE(vchPubKey);
        READWRITE(vchSig);
    }
};

/** Reserve attestation (ARCH s6): the house proves it controls amountReserves
 * sats of PLAIN (untagged) liquid base coin, verified per-outpoint against the
 * PARENT-chain UTXO state - order-independent within a block; a coin spent
 * earlier in the same block does not falsify the snapshot. Floor logic (T2/T4)
 * runs on acceptance: below rho -> Stressed; at/above rho + buffer -> recovery;
 * in-band -> state preserved. The three nPrev* fields are undo priors: connect
 * requires them to equal the DB values, so DisconnectBlock restores exactly and
 * a replayed attestation always fails (structural replay protection - with the
 * nAsOfHeight monotone rule, no prevouts binding needed). */
struct HouseAttest {
    uint32_t nHouseID;                     // leading - mempool-guard convention
    uint8_t nSchemaVersion;                // = 1 (D11); v2+ adds fields by bump
    uint32_t nAsOfHeight;                  // freshness anchor + challenge binding
    uint32_t nPrevLastAttestHeight;        // undo priors (must match DB at connect)
    uint32_t nPrevStressSince;
    CAmount amountPrevReserves;
    // Deferral priors (3.5): a RECOVERY attestation lifts an invoked option
    // clause, so the attest undo must restore that state too. DR-2 adds the
    // episode-end stamp (a recovery writes nDeferEndedHeight = connect height).
    uint32_t nPrevDeferInvokedHeight;
    uint32_t nPrevDeferRenewals;
    uint32_t nPrevDeferCumBlocks;
    uint32_t nPrevDeferEndedHeight;
    CAmount amountReserves;                // must equal the sum of proof coin values
    std::vector<AttestProof> vProofs;      // <= MAX_ATTEST_PROOFS, unique outpoints
    std::vector<uint32_t> vApproverIndex;  // strictly ascending, M-of-N
    std::vector<std::vector<unsigned char>> vApproverSig;

    HouseAttest() : nHouseID(0), nSchemaVersion(1), nAsOfHeight(0),
                    nPrevLastAttestHeight(0), nPrevStressSince(0),
                    amountPrevReserves(0), nPrevDeferInvokedHeight(0),
                    nPrevDeferRenewals(0), nPrevDeferCumBlocks(0),
                    nPrevDeferEndedHeight(0), amountReserves(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(nSchemaVersion);
        READWRITE(nAsOfHeight);
        READWRITE(nPrevLastAttestHeight);
        READWRITE(nPrevStressSince);
        READWRITE(amountPrevReserves);
        READWRITE(nPrevDeferInvokedHeight);
        READWRITE(nPrevDeferRenewals);
        READWRITE(nPrevDeferCumBlocks);
        READWRITE(nPrevDeferEndedHeight);
        READWRITE(amountReserves);
        READWRITE(vProofs);
        READWRITE(vApproverIndex);
        READWRITE(vApproverSig);
    }
};

/** DEFER (ARCH s7 Option (c)): the house invokes the option clause. Valid only
 * at effective Stressed - not at Open (nothing to defer), not at Insolvent
 * (sim-D1: "insolvency -> resolution, never suspension"). Invocation REPLACES
 * the remaining stress clock with the deferral window; redemption stops being
 * paid at par and is QUEUED instead (R-i3), accruing interest from the date of
 * demand. Recovery (an attestation at floor+buffer) lifts it; window expiry
 * without recovery goes to Insolvent.
 *
 * This does not GRANT the house a suspension power - REDEEM is dual-signed, so
 * a house can already refuse to pay, silently, for free, forever. The clause
 * makes that power LEGIBLE (declared on-chain), TIME-BOUNDED (the window),
 * COMPENSATED (interest) and PENALISED (confidence death). It disciplines a
 * power that already exists. */
struct HouseDefer {
    uint32_t nHouseID;                     // leading - mempool-guard convention
    uint32_t nPrevLastActivation;          // undo prior (must match DB at connect)
    // vout[0] MUST lock the house's attested till into consensus custody:
    // an escrow-script output worth at least amountLastAttestReserves, on a
    // FRESH attestation (D11). A house that attested reserves it no longer
    // holds therefore cannot suspend at all - it must first re-attest, truthfully
    // and lower, and lock what it actually has. Suspension is not free.
    std::vector<uint32_t> vApproverIndex;
    std::vector<std::vector<unsigned char>> vApproverSig;

    HouseDefer() : nHouseID(0), nPrevLastActivation(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(nPrevLastActivation);
        READWRITE(vApproverIndex);
        READWRITE(vApproverSig);
    }
};

/** RENEW: extend the current deferral by one further window. At most
 * HOUSE_DEFER_MAX_RENEWALS per episode (sim D2: "one renewal max"). */
struct HouseRenew {
    uint32_t nHouseID;
    std::vector<uint32_t> vApproverIndex;
    std::vector<std::vector<unsigned char>> vApproverSig;

    HouseRenew() : nHouseID(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(vApproverIndex);
        READWRITE(vApproverSig);
    }
};

/** RELEASE (Phase 3.5 D11): once the clause has been LIFTED (the house is
 * effectively Open again), the house takes its locked till back out of consensus
 * custody so it can pay the queued holders. Valid only at effective Open, spends
 * only reserve-lock coins, M-of-N approved with the destination bound. While the
 * house is Stressed, Deferred or Insolvent the till stays where the holders can
 * reach it. */
struct HouseRelease {
    uint32_t nHouseID;
    std::vector<uint32_t> vApproverIndex;
    std::vector<std::vector<unsigned char>> vApproverSig;

    HouseRelease() : nHouseID(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(vApproverIndex);
        READWRITE(vApproverSig);
    }
};

/** Reclaim a tail-expired (or solo wound-down) pledge: spends the partner's
 * pledge UTXO(s). Signature binds hashOutputs (destination), Bills-RETIRE
 * pattern. Valid when partner status == tail AND height >= nTailUnlockHeight. */
struct HouseReclaim {
    uint32_t nHouseID;
    uint32_t nPartnerIndex;
    std::vector<unsigned char> vchSig;

    HouseReclaim() : nHouseID(0), nPartnerIndex(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(nPartnerIndex);
        READWRITE(vchSig);
    }
};

//
// Pure helpers (house.cpp)
//

/** Canonical house identity: sha256 over the founding declaration (content-
 * derived like bill_id - the registration txid cannot appear in its own
 * outputs' escrow script). Uniqueness rides on strClassID uniqueness. */
uint256 HouseIDFromDeclaration(const HouseRegister& reg);

/** Digest of the declaration fields every founding signature commits to. */
uint256 HouseDeclarationDigest(const HouseRegister& reg);

uint256 HouseRegisterSigHash(const uint256& declDigest, uint32_t nPartnerIndex, const CAmount& amountPledge);
uint256 HouseTopupSigHash(const uint256& houseID, uint32_t nPartnerIndex, const uint256& hashOutputs);
uint256 HouseAdmitSigHash(const uint256& houseID, const std::vector<unsigned char>& vchNewPubKey, const CAmount& amountPledge);
uint256 HouseExitSigHash(const uint256& houseID, uint32_t nPartnerIndex, const uint256& hashOutputs);
uint256 HouseWinddownSigHash(const uint256& houseID, const uint256& hashOutputs);
uint256 HouseReclaimSigHash(const uint256& houseID, uint32_t nPartnerIndex, const uint256& hashOutputs);
uint256 HouseDeferSigHash(const uint256& houseID, uint32_t nPrevLastActivation, const uint256& hashOutputs);
uint256 HouseRenewSigHash(const uint256& houseID, uint32_t nRenewalIndex, const uint256& hashPrevouts, const uint256& hashOutputs);
uint256 HouseReleaseSigHash(const uint256& houseID, const uint256& hashPrevouts, const uint256& hashOutputs);

/** Confidence death (sim D15 / D13a): true when a FURTHER deferral invocation
 * must be refused - a second activation inside HOUSE_CD_WINDOW_BLOCKS, or
 * cumulative suspension already beyond HOUSE_CD_MAX_SUSPENDED. This is a GUARD,
 * not a kill switch: the house is not executed, it simply loses the crisis tool
 * and falls back to the ordinary stress clock, which is what kills it. */
bool HouseConfidenceDead(const CHouse& house, int nHeight);

/** The per-coin reserve-proof challenge: sha256d over a domain tag, the house
 * identity (cross-house replay bar), the as-of height AND that height's block
 * hash on the validating branch (recency: a reorg past nAsOfHeight invalidates
 * every proof), and the outpoint itself. Signed by the coin's own key. */
uint256 HouseAttestChallenge(const uint256& houseID, uint32_t nAsOfHeight,
                             const uint256& hashAsOfBlock, const COutPoint& outpoint);

/** Digest of the proof set (outpoint + owner key per entry; NOT the proof
 * signatures, which may be gathered in parallel after the set is fixed). */
uint256 HouseAttestProofSetHash(const std::vector<AttestProof>& vProofs);

/** What the M-of-N approvers sign: house identity, as-of height, the claimed
 * reserve total, the proof set, and the exact output set of the carrier tx. */
uint256 HouseAttestSigHash(const uint256& houseID, uint32_t nAsOfHeight,
                           const CAmount& amountReserves, const uint256& hashProofSet,
                           const uint256& hashOutputs);

/** Pledge escrow lock: <house_id> OP_DROP OP_TRUE (Bills-D1 family). */
CScript HouseEscrowScript(const uint256& houseID);
bool IsHouseEscrowScript(const CScript& script);

/** True if strClassID is [a-z0-9]{1,MAX_HOUSE_CLASS_ID_BYTES}. */
bool IsValidHouseClassID(const std::string& strClassID);

/** The effective stress origin of a house at nHeight: the stored ratio-breach
 * height (nStressSinceHeight), the derived missed-cadence deadline + 1 if that
 * is earlier (or the only origin), or 0 if the house is not stressed. */
uint32_t HouseStressOrigin(const CHouse& house, int nHeight);

/** The consensus status of a house AT nHeight, deriving the two height-
 * triggered transitions lazily from stored fields (D3 - no sweeps, no
 * automatic state writes, nothing new to undo):
 *   - missed cadence:  no accepted attestation for MISS_N * CADENCE blocks
 *     past nLastAttestHeight  ->  Stressed from that deadline + 1;
 *   - window expiry:   Stressed (either origin) for HOUSE_STRESSED_WINDOW
 *     blocks  ->  Insolvent.
 * Stored 'i' (materialized by the first waterfall claim) and 'w' short-
 * circuit. Effective 'i' is absorbing without writes because every op that
 * could change the derivation inputs is rejected at effective 'i'. */
char HouseEffectiveStatus(const CHouse& house, int nHeight);

/** The nStressSinceHeight value an accepted attestation of amountReserves at
 * nHeight leaves behind (T2 below-floor / T4 recovery-with-hysteresis /
 * in-band preserve; D9). Pure - the write itself happens in the ATTEST
 * contextual branch. */
uint32_t HouseAttestNewStressOrigin(const CHouse& house, const CAmount& amountReserves, int nHeight);

/** CAPITAL cap (CM-2): lambda_tier * active escrow. */
uint64_t HouseCapitalCapUnits(const CHouse& house);

/** RESERVE cap (Phase 3.5 D2, the rho-at-mint gate): the note units the
 * house's ATTESTED liquid till supports, N <= R / rho. Zero for a house that
 * has never attested - so a new house must attest before it can mint. */
uint64_t HouseReserveCapUnits(const CHouse& house);

/** The binding mint cap: min(capital, reserve). CM-2 always specified the
 * PAIR; 3.4 enforced rho only retroactively at attestation. */
uint64_t HouseMintCapUnits(const CHouse& house);

/** The house's ATTESTED reserve ratio in basis points (R / N). Returns 10000
 * (100%) when there are no liabilities. This is the last ATTESTED value, not a
 * live one - consensus cannot see the till between attestations, which is also
 * why a house that lets its attestation go stale keeps charging whatever spread
 * its last report implied: the incentive points at attesting. */
uint32_t HouseAttestedRatioBps(const CHouse& house);

/** The dynamic-brassage spread, basis points, from the attested ratio (D1/D8).
 * Zero at or above rho (PAR while Open); ramps quadratically - the sim's
 * prox^2, so it opens gently rather than with a cliff at the floor - to
 * HOUSE_BRASSAGE_MAX_BPS at or below theta. */
uint32_t HouseBrassageBps(const CHouse& house);

/** The spread owed on redeeming nUnits at nBps. Floor division; 128-bit. */
CAmount HouseBrassageAmount(uint64_t nUnits, uint32_t nBps);

/** Weighted-average REMAINING term (blocks) of the house's outstanding term
 * deposits at height nHeight: (Sigma(principal*maturity) / Sigma(principal)) -
 * nHeight, clamped to >= 0. 0 if no deposits. 128-bit intermediate (Phase 3.8). */
uint32_t HouseDepositWAM(const CHouse& house, int nHeight);

/** Weighted-average maturity of the DEPOSIT-FUNDED slice of the loan book -
 * max(0, L - escrow_capacity). A v1 STUB returning 0: no discounting op exists,
 * so L is structurally 0. The forward hook for the discounting module. */
uint32_t HouseLoanBookSliceWAM(const CHouse& house, int nHeight);

/** The consensus match-funding rule (attestation-checked): the deposits'
 * weighted-average maturity must be >= that of the deposit-funded loan slice, so
 * a house cannot fund long assets with short money. VACUOUSLY TRUE in v1 (the
 * loan slice is 0); ships now, enforces for real when discounting lands. */
bool HouseMatchFundingOK(const CHouse& house, int nHeight);

template <typename T>
bool DecodeHousePayload(const std::vector<unsigned char>& vch, T& payload);

/** Context-free shape rules for v12 house txs (no DB, no sig verification -
 * ECDSA runs contextually in CheckHouseOperation, Bills DoS-pricing pattern). */
bool CheckHouseTransactionShape(const CTransaction& tx, CValidationState& state);

#endif // BITCOIN_HOUSE_H
