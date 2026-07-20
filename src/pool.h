// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POOL_H
#define BITCOIN_POOL_H

#include <amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <string>
#include <vector>

class CValidationState;
class Coin;

//
// Note<->BTX liquidity pools (Phase 3.7 part 1) - the AMM core of clearing.
//
// A pool is a constant-product (x*y=k) venue holding a house's note-units on
// one side and base sats on the other. It is the market that prices note and
// deposit-receipt early exits (ARCH s5A.2/s8) and carries NO FreeBank-specific
// economics - the par-attractor / settlement layer is a separate, CM-3-gated,
// multi-house-era increment.
//
// v1 invariants:
// - ONE pool per house, and nPoolID == nHouseID. The id is known pre-connect,
//   so every payload is self-contained and AddCoins self-tags (note model -
//   never thread an id through ConnectBlock).
// - CREATE_POOL is house-approved (M-of-N) and requires effective-Open; every
//   other pool op is house-status-UNGATED (the pool is the secondary market -
//   the legitimate exit from a suspended house is selling at a discount).
// - ONE pool op per pool per block: each op binds the pool's PRIOR state
//   byte-exact in its payload, giving deterministic payload-only undo and
//   structurally eliminating intra-block sandwiching.
// - Custody = exactly TWO canonical pool-escrow coins after every op, at
//   fixed vout[0] (note side, dual-tagged fNote+fPoolEscrow) and vout[1]
//   (BTX side, fPoolEscrow). CPool records both outpoints.
// - Pool ops NEVER mint or burn note-units (sum in == sum out), so
//   nMintedUnits / the lambda-cap / winddown / the insolvency snapshot are
//   all untouched by pooling. The ONE documented exception is the terminal
//   POOL_OP_RETIRE, which burns the residual locked-floor note-units (X) from
//   nMintedUnits as it deletes the pool record - the teardown that lets a
//   house that ever chartered a pool bring its liabilities to 0 and reach
//   WINDDOWN / the whole-house final settle (design-item-28, decision 1).
// - Only UNDEMANDED notes (nDemandHeight == 0) may enter a pool.
//
// All constants PROVISIONAL (P-1) - revisit before real value.
//

// Pool operations carried by TRANSACTION_POOL_VERSION transactions
static const uint8_t POOL_OP_CREATE     = 1;   // house charters its venue + seeds liquidity
static const uint8_t POOL_OP_ADD_LIQ    = 2;   // provider adds note+BTX, receives LP shares
static const uint8_t POOL_OP_REMOVE_LIQ = 3;   // provider burns LP shares, takes pro-rata
static const uint8_t POOL_OP_SWAP       = 4;   // trader swaps note<->BTX at x*y=k
static const uint8_t POOL_OP_RETIRE     = 5;   // terminal: close a floored pool, burn its residual, delete the record

// Dust base-value carried by the note-side escrow coin and LP-share coins
// (they hold claims, not value).
static const CAmount POOL_DUST_VALUE = 1000;

// LP units permanently locked at CREATE (subtracted from the creator's mint,
// never redeemable): the Uniswap-v2 floor that stops the pool ever draining
// to zero reserves and bounds share-price manipulation of the first mint.
static const uint64_t POOL_MIN_LIQUIDITY = 1000;

// Swap fee bounds; the fee is fixed per pool at CREATE and accrues to the
// reserves (LPs). PROVISIONAL (P-1).
static const uint32_t POOL_FEE_BPS_MIN = 1;
static const uint32_t POOL_FEE_BPS_MAX = 100;
static const uint32_t POOL_FEE_BPS_DEFAULT = 30;

// Max LP-share inputs one REMOVE_LIQ may burn (bounds per-tx loops).
static const size_t MAX_POOL_LP_INPUTS = 100;

// Magnitude ceiling for every pool quantity (note units, sats, LP units).
// Note units per house are bounded by the lambda cap at 3*MAX_MONEY; sats by
// MAX_MONEY; the initial LP supply is sqrt(note*btx) < 3*MAX_MONEY. Bounding
// all inputs here makes the unsigned __int128 helper arithmetic provably
// overflow-free: 3*MAX_MONEY < 2^53, so in*(10^4)*reserve < 2^(53+14+53) =
// 2^120 < 2^128.
static const uint64_t POOL_MAX_AMOUNT = (uint64_t)3 * (uint64_t)MAX_MONEY;

// CPool serialization version (fresh record, no migrations yet).
static const uint8_t POOL_SER_VERSION = 1;

// Payload ceiling: the largest op (CREATE) is ~1.5KB at 15 approver sigs.
static const size_t MAX_POOL_PAYLOAD = 4096;

/** The pool record (PoolDB, blocks/Pools/). Reserves mirror the two canonical
 * escrow coins byte-exact; every op's payload binds the prior (nNoteReserve,
 * amountBtxReserve, nLpSupply) so DisconnectBlock restores the record from the
 * payload alone (ATTEST pattern) and a second same-block op cannot connect. */
class CPool
{
public:
    uint32_t nPoolID;          // == nHouseID (v1: one pool per house)
    uint32_t nFeeBps;          // fixed at CREATE, bounds [POOL_FEE_BPS_MIN, POOL_FEE_BPS_MAX]
    uint64_t nNoteReserve;     // X: note-units held (the fNote+fPoolEscrow coin at outNote)
    CAmount amountBtxReserve;  // Y: base sats held (the fPoolEscrow coin at outBtx)
    uint64_t nLpSupply;        // S: total LP units incl. the locked POOL_MIN_LIQUIDITY
    COutPoint outNote;         // canonical note-side escrow coin (vout[0] of the last op)
    COutPoint outBtx;          // canonical BTX-side escrow coin (vout[1] of the last op)
    int32_t nCreateHeight;

    CPool() { SetNull(); }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        uint8_t nSerVersion = POOL_SER_VERSION;
        READWRITE(nSerVersion);
        if (ser_action.ForRead() && nSerVersion > POOL_SER_VERSION)
            throw std::ios_base::failure("CPool: unknown serialization version");
        READWRITE(nPoolID);
        READWRITE(nFeeBps);
        READWRITE(nNoteReserve);
        READWRITE(amountBtxReserve);
        READWRITE(nLpSupply);
        READWRITE(outNote);
        READWRITE(outBtx);
        READWRITE(nCreateHeight);
    }

    void SetNull()
    {
        nPoolID = 0;
        nFeeBps = 0;
        nNoteReserve = 0;
        amountBtxReserve = 0;
        nLpSupply = 0;
        outNote.SetNull();
        outBtx.SetNull();
        nCreateHeight = 0;
    }

    bool IsNull() const { return nPoolID == 0 && nLpSupply == 0; }
};

//
// Op payloads (tx v15 trailer). nPoolID is LEADING in every payload: the ATMP
// cross-op guard identifies the pool by memcpying the first 4 decoded bytes,
// and CREATE additionally joins the HOUSE one-op guard with the same 4 bytes
// (nPoolID == nHouseID). Every tagged output's units are carried EXPLICITLY
// (NoteTransfer's vUnits precedent) so AddCoins self-tags from the payload
// alone - in particular SWAP carries nAmountOut because the fee lives in the
// CPool record, not the payload, so the output units could not be recomputed
// payload-pure. ADD/REMOVE/SWAP bind the pool's PRIOR (X, Y, S) byte-exact:
// the contextual check rejects on any mismatch, which is what makes one op
// per pool per block self-enforcing and the undo payload-only.
//

/** CREATE: the house charters its venue (M-of-N approval, effective-Open) and
 * the creator seeds both sides. vout[0] = note escrow (units=nInitNoteUnits),
 * vout[1] = BTX escrow (value=amountInitBtx), vout[2] = creator LP coin
 * (units = isqrt(init product) - POOL_MIN_LIQUIDITY), optional vout[3] = note
 * change back to the creator (present iff nNoteChangeUnits > 0). */
struct PoolCreate {
    uint32_t nPoolID;                                     // LEADING (== nHouseID)
    uint32_t nFeeBps;                                     // fixed for the pool's life
    uint64_t nInitNoteUnits;
    int64_t amountInitBtx;
    uint64_t nNoteChangeUnits;                            // 0 = no note-change output
    std::vector<unsigned char> vchCreatorPubKey;          // must hash to every spent note input; receives LP + change
    std::vector<unsigned char> vchCreatorSig;
    std::vector<uint32_t> vApproverIndex;                 // strictly ascending
    std::vector<std::vector<unsigned char>> vApproverSig;

    PoolCreate() : nPoolID(0), nFeeBps(0), nInitNoteUnits(0), amountInitBtx(0), nNoteChangeUnits(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nPoolID);
        READWRITE(nFeeBps);
        READWRITE(nInitNoteUnits);
        READWRITE(amountInitBtx);
        READWRITE(nNoteChangeUnits);
        READWRITE(vchCreatorPubKey);
        READWRITE(vchCreatorSig);
        READWRITE(vApproverIndex);
        READWRITE(vApproverSig);
    }
};

/** ADD_LIQ: vin[0/1] = the pool's escrow pair, then the provider's note coins
 * and plain funding. vout[0/1] = new escrow pair (X+add, Y+add), vout[2] = LP
 * coin to the provider (nLpMinted, consensus-checked against the min-rule
 * formula), optional vout[3] = note change. */
struct PoolAddLiq {
    uint32_t nPoolID;
    uint64_t nPriorNoteReserve;                           // X - must equal CPool byte-exact
    int64_t amountPriorBtxReserve;                        // Y
    uint64_t nPriorLpSupply;                              // S
    uint64_t nAddNoteUnits;
    int64_t amountAddBtx;
    uint64_t nLpMinted;                                   // == PoolLpMintProportional(...)
    uint64_t nNoteChangeUnits;                            // 0 = no note-change output
    std::vector<unsigned char> vchProviderPubKey;         // must hash to every spent note input; receives LP + change
    std::vector<unsigned char> vchProviderSig;

    PoolAddLiq() : nPoolID(0), nPriorNoteReserve(0), amountPriorBtxReserve(0), nPriorLpSupply(0),
                   nAddNoteUnits(0), amountAddBtx(0), nLpMinted(0), nNoteChangeUnits(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nPoolID);
        READWRITE(nPriorNoteReserve);
        READWRITE(amountPriorBtxReserve);
        READWRITE(nPriorLpSupply);
        READWRITE(nAddNoteUnits);
        READWRITE(amountAddBtx);
        READWRITE(nLpMinted);
        READWRITE(nNoteChangeUnits);
        READWRITE(vchProviderPubKey);
        READWRITE(vchProviderSig);
    }
};

/** REMOVE_LIQ: vin[0/1] = escrow pair, vin[2..] = the provider's LP coins
 * (whole coins; partial burns take LP change). vout[0/1] = new escrow pair,
 * vout[2] = note payout (fNote, units=nNoteOut), vout[3] = BTX payout
 * (value=amountBtxOut), optional vout[4] = LP change (nLpChangeUnits > 0). */
struct PoolRemoveLiq {
    uint32_t nPoolID;
    uint64_t nPriorNoteReserve;
    int64_t amountPriorBtxReserve;
    uint64_t nPriorLpSupply;
    uint64_t nBurnLp;
    uint64_t nNoteOut;                                    // == floor(burn*X/S)
    int64_t amountBtxOut;                                 // == floor(burn*Y/S)
    uint64_t nLpChangeUnits;                              // 0 = no LP-change output
    std::vector<unsigned char> vchProviderPubKey;         // must hash to every spent LP input; receives payouts
    std::vector<unsigned char> vchProviderSig;

    PoolRemoveLiq() : nPoolID(0), nPriorNoteReserve(0), amountPriorBtxReserve(0), nPriorLpSupply(0),
                      nBurnLp(0), nNoteOut(0), amountBtxOut(0), nLpChangeUnits(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nPoolID);
        READWRITE(nPriorNoteReserve);
        READWRITE(amountPriorBtxReserve);
        READWRITE(nPriorLpSupply);
        READWRITE(nBurnLp);
        READWRITE(nNoteOut);
        READWRITE(amountBtxOut);
        READWRITE(nLpChangeUnits);
        READWRITE(vchProviderPubKey);
        READWRITE(vchProviderSig);
    }
};

// SWAP directions
static const uint8_t POOL_SWAP_NOTE_TO_BTX = 1;
static const uint8_t POOL_SWAP_BTX_TO_NOTE = 2;

/** SWAP: vin[0/1] = escrow pair, then the trader's coins. Direction 1
 * (note->BTX): vout[0] = note escrow (X+in), vout[1] = BTX escrow (Y-out),
 * vout[2] = BTX payout (value=nAmountOut), optional vout[3] = note change.
 * Direction 2 (BTX->note): vout[0] = note escrow (X-out), vout[1] = BTX
 * escrow (Y+in), vout[2] = note payout (units=nAmountOut); trader note inputs
 * are FORBIDDEN. nMinOut is the consensus slippage guard; nAmountOut is
 * consensus-checked against PoolSwapOut(...). */
struct PoolSwap {
    uint32_t nPoolID;
    uint64_t nPriorNoteReserve;
    int64_t amountPriorBtxReserve;
    uint64_t nPriorLpSupply;
    uint8_t nDirection;
    uint64_t nAmountIn;
    uint64_t nMinOut;
    uint64_t nAmountOut;                                  // == PoolSwapOut(...)
    uint64_t nNoteChangeUnits;                            // dir 1 only; 0 = no note-change output
    std::vector<unsigned char> vchTraderPubKey;           // must hash to every spent note input (dir 1); receives payout
    std::vector<unsigned char> vchTraderSig;

    PoolSwap() : nPoolID(0), nPriorNoteReserve(0), amountPriorBtxReserve(0), nPriorLpSupply(0),
                 nDirection(0), nAmountIn(0), nMinOut(0), nAmountOut(0), nNoteChangeUnits(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nPoolID);
        READWRITE(nPriorNoteReserve);
        READWRITE(amountPriorBtxReserve);
        READWRITE(nPriorLpSupply);
        READWRITE(nDirection);
        READWRITE(nAmountIn);
        READWRITE(nMinOut);
        READWRITE(nAmountOut);
        READWRITE(nNoteChangeUnits);
        READWRITE(vchTraderPubKey);
        READWRITE(vchTraderSig);
    }
};

/** RETIRE: the terminal op. Valid only on a pool sitting at the locked floor
 * (nLpSupply == POOL_MIN_LIQUIDITY, i.e. every issued LP share removed), it
 * spends the canonical custody pair (vin[0]=outNote, vin[1]=outBtx), BURNS the
 * residual note-units X from house.nMintedUnits (the one documented terminal
 * exception to "pool ops never burn units"), force-pays the floor BTX Y to
 * vout[0]=P2PKH(house.vchRedemptionDestPK), and deletes the CPool record. No
 * output is tagged (nothing re-issued). The payload carries the FULL prior
 * record (incl. nFeeBps + nCreateHeight) so DisconnectBlock rebuilds it
 * payload-only. Hybrid auth, EXACTLY ONE path populated (HouseExit dual-auth
 * precedent, but mutually exclusive - the paths carry different status
 * conditions, resolved contextually):
 *   - single-partner (insolvency liveness): nTriggerPartnerIndex + vchTriggerSig,
 *     accepted only when HouseEffectiveStatus == INSOLVENT (mirrors the SETTLE
 *     trigger bar so liveness never depends on assembling M-of-N);
 *   - M-of-N (any status): vApproverIndex[] + vApproverSig[], with
 *     vchTriggerSig empty and nTriggerPartnerIndex pinned to 0. */
struct PoolRetire {
    uint32_t nPoolID;                                     // LEADING (== nHouseID)
    uint64_t nPriorNoteReserve;                           // X - must equal CPool byte-exact
    int64_t amountPriorBtxReserve;                        // Y
    uint64_t nPriorLpSupply;                              // S - must == POOL_MIN_LIQUIDITY
    uint32_t nFeeBps;                                     // full prior record (undo byte-exactness)
    int32_t nCreateHeight;                                // full prior record (undo byte-exactness)
    uint32_t nTriggerPartnerIndex;                        // single-partner path; 0 on the M-of-N path
    std::vector<unsigned char> vchTriggerSig;             // empty <=> M-of-N path
    std::vector<uint32_t> vApproverIndex;                 // empty <=> single-partner path; strictly ascending
    std::vector<std::vector<unsigned char>> vApproverSig;

    PoolRetire() : nPoolID(0), nPriorNoteReserve(0), amountPriorBtxReserve(0), nPriorLpSupply(0),
                   nFeeBps(0), nCreateHeight(0), nTriggerPartnerIndex(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nPoolID);
        READWRITE(nPriorNoteReserve);
        READWRITE(amountPriorBtxReserve);
        READWRITE(nPriorLpSupply);
        READWRITE(nFeeBps);
        READWRITE(nCreateHeight);
        READWRITE(nTriggerPartnerIndex);
        READWRITE(vchTriggerSig);
        READWRITE(vApproverIndex);
        READWRITE(vApproverSig);
    }
};

//
// Pure helpers (pool.cpp)
//

/** Domain-separated 32-byte escrow tag for a pool: sha256d over
 * ("FreeBankPoolEscrow", nPoolID). Distinguishes the pool's open-at-script
 * escrow from house escrow (whose 32-byte push is the declaration hash) and
 * bill escrow (the encrypted-body hash) at the SCRIPT level; the real
 * protection is the fPoolEscrow coin-tag spend guard. */
uint256 PoolEscrowTag(uint32_t nPoolID);

/** The escrow output script: <PoolEscrowTag> OP_DROP OP_TRUE - open at script
 * level, protected by the tx_verify tag guard (bills/houses pattern). */
CScript PoolEscrowScript(uint32_t nPoolID);
bool IsPoolEscrowScript(const CScript& script);

/** LP-share UTXO lock: standard P2PKH to the provider. Share-ness rides the
 * coin tag (fLpShare + nPoolID + nLpUnits), never the script. */
CScript PoolScriptForPubKey(const std::vector<unsigned char>& vchPubKey);

/** floor(sqrt(a*b)) - the CREATE LP supply. Inputs bounded by POOL_MAX_AMOUNT
 * so the u128 product < 2^106 and the root fits u64. Returns 0 if either
 * input is 0 or out of bounds. */
uint64_t PoolIsqrtProduct(uint64_t a, uint64_t b);

/** CREATE: initial LP supply S0 = floor(sqrt(initNote*initBtx)). Requires
 * S0 > POOL_MIN_LIQUIDITY (the creator's coin carries S0 - POOL_MIN_LIQUIDITY;
 * the locked floor stays in nLpSupply forever). False on bounds/zero/floor. */
bool PoolLpMintInitial(uint64_t nInitNote, CAmount amountInitBtx, uint64_t& nLpToCreator, uint64_t& nLpSupply0);

/** ADD_LIQ: minted L = min(addNote*S/X, addBtx*S/Y), floors (unbalanced adds
 * donate the excess to the pool - Uniswap-v2 semantics). Requires L >= 1 and
 * S + L within bounds. False on bounds/zero. */
bool PoolLpMintProportional(uint64_t nAddNote, CAmount amountAddBtx,
                            uint64_t nNoteReserve, CAmount amountBtxReserve, uint64_t nLpSupply,
                            uint64_t& nLpMinted);

/** REMOVE_LIQ: noteOut = floor(burn*X/S), btxOut = floor(burn*Y/S). Requires
 * burn >= 1 and S - burn >= POOL_MIN_LIQUIDITY (the pool never fully drains).
 * A payout side that floors to 0 is returned as 0 and OMITTED downstream (the
 * zero-side companion - a full-position burn is always valid, so the floor is
 * always reachable); only a burn paying NOTHING (both sides 0) is rejected. */
bool PoolLpRedeemAmounts(uint64_t nBurnLp,
                         uint64_t nNoteReserve, CAmount amountBtxReserve, uint64_t nLpSupply,
                         uint64_t& nNoteOut, CAmount& amountBtxOut);

/** SWAP: out = floor(inFee*reserveOut / (reserveIn*10000 + inFee)) with
 * inFee = amountIn*(10000 - feeBps). Fee accrues to reserves; floor rounding
 * is always in the pool's favor, so k = x*y never decreases across a swap.
 * Requires amountIn >= 1, out >= 1 and out < reserveOut (the pool keeps at
 * least one unit of each side). False on bounds/fee-range/zero. */
bool PoolSwapOut(uint64_t nAmountIn, uint64_t nReserveIn, uint64_t nReserveOut,
                 uint32_t nFeeBps, uint64_t& nAmountOut);

/** SHA256d over every input outpoint of tx - bound into EVERY pool sighash
 * (R-i6: bind prevouts wherever a payload signature is an authorization). */
uint256 PoolHashPrevouts(const CTransaction& tx);

uint256 PoolCreateSigHash(uint32_t nPoolID, uint32_t nFeeBps, uint64_t nInitNoteUnits,
                          int64_t amountInitBtx, uint64_t nNoteChangeUnits,
                          const uint256& hashPrevouts, const uint256& hashOutputs);
uint256 PoolAddLiqSigHash(const PoolAddLiq& add, const uint256& hashPrevouts, const uint256& hashOutputs);
uint256 PoolRemoveLiqSigHash(const PoolRemoveLiq& rem, const uint256& hashPrevouts, const uint256& hashOutputs);
uint256 PoolSwapSigHash(const PoolSwap& swap, const uint256& hashPrevouts, const uint256& hashOutputs);
uint256 PoolRetireSigHash(const PoolRetire& ret, const uint256& hashPrevouts, const uint256& hashOutputs);

template <typename T>
bool DecodePoolPayload(const std::vector<unsigned char>& vch, T& payload);

/** Tag output n of a v15 pool tx from the PAYLOAD ALONE. The single tagger
 * shared by AddCoins (connect AND rollforward), the mempool view, and the
 * wallet's AvailableCoins skip - one code path, so connect == replay ==
 * mempool == wallet by construction (the untagged-escrow CRITICAL class
 * cannot recur as a divergence between sites). No-op for non-pool txs and
 * untagged positions. */
void ApplyPoolCoinTags(const CTransaction& tx, uint32_t n, Coin& coin);

/** Context-free shape rules for v15 pool txs (no DB, no ECDSA - priors,
 * formulas, sums vs inputs and signatures run contextually in
 * CheckPoolOperation, DoS pricing). Escrow scripts/values at vout[0/1] and
 * the fixed tagged-output positions ARE checked here: they derive from the
 * payload alone. */
bool CheckPoolTransactionShape(const CTransaction& tx, CValidationState& state);

#endif // BITCOIN_POOL_H
