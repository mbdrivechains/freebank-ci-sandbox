// Copyright (c) 2017-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_verify.h>

#include <bill.h>
#include <house.h>
#include <note.h>
#include <deposit.h>
#include <pool.h>
#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <consensus/validation.h>

// TODO remove the following dependencies
#include <chain.h>
#include <coins.h>
#include <utilmoneystr.h>

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // tx.nVersion is signed integer so requires cast to unsigned otherwise
    // we would be doing a signed comparison and half the range of nVersion
    // wouldn't support BIP 68.
    bool fEnforceBIP68 = static_cast<uint32_t>(tx.nVersion) >= 2
                      && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight-1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, int flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, &tx.vin[i].scriptWitness, flags);
    }
    return nSigOps;
}

bool CheckTransaction(const CTransaction& tx, CValidationState &state, bool fCheckDuplicateInputs)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");


    bool fAssetGenesis = tx.nVersion == TRANSACTION_BITASSET_CREATE_VERSION;

    // BitAsset genesis transactions must have at least 2 outputs
    if (fAssetGenesis && tx.vout.size() < 2)
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-asset-gen-vout-size");

    // Bill transactions: context-free shape + payload-signature checks
    if (tx.nVersion == TRANSACTION_BILL_VERSION) {
        if (!CheckBillTransactionShape(tx, state))
            return false;
    }

    // House transactions: context-free shape checks
    if (tx.nVersion == TRANSACTION_HOUSE_VERSION) {
        if (!CheckHouseTransactionShape(tx, state))
            return false;
    }

    // Note transactions: context-free shape checks
    if (tx.nVersion == TRANSACTION_NOTE_VERSION) {
        if (!CheckNoteTransactionShape(tx, state))
            return false;
    }

    // Term-deposit transactions (Phase 3.8): context-free shape checks
    if (tx.nVersion == TRANSACTION_DEPOSIT_VERSION) {
        if (!CheckDepositTransactionShape(tx, state))
            return false;
    }

    // Pool transactions (Phase 3.7): context-free shape checks
    if (tx.nVersion == TRANSACTION_POOL_VERSION) {
        if (!CheckPoolTransactionShape(tx, state))
            return false;
    }

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    std::vector<CTxOut>::const_iterator it;
    // Skip BitAsset genesis outputs
    fAssetGenesis ? it = tx.vout.begin() + 2 : it = tx.vout.begin();
    for (; it != tx.vout.end(); it++)
    {
        if (it->nValue < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (it->nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += it->nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs - note that this check is slow so we skip it in CheckBlock
    if (fCheckDuplicateInputs) {
        std::set<COutPoint> vInOutPoints;
        for (const auto& txin : tx.vin)
        {
            if (!vInOutPoints.insert(txin.prevout).second)
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
        }
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
    }

    return true;
}

bool Consensus::CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, CAmount& txfee)
{
    // are the actual inputs available?
    if (!inputs.HaveInputs(tx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-missingorspent", false,
                         strprintf("%s: inputs missing/spent", __func__));
    }

    // For a note TRANSFER/REDEEM, every spent note coin must be a P2PKH to the
    // declared sender/holder (so the payload sig actually authorizes THESE
    // notes). Decode once up front; the payload already passed shape.
    CScript expectedNoteScript;
    bool fHaveExpectedNote = false;
    if (tx.nVersion == TRANSACTION_NOTE_VERSION) {
        if (tx.nNoteOp == NOTE_OP_TRANSFER) {
            NoteTransfer x;
            if (DecodeNotePayload(tx.vchNotePayload, x)) { expectedNoteScript = NoteScriptForPubKey(x.vchSenderPubKey); fHaveExpectedNote = true; }
        } else if (tx.nNoteOp == NOTE_OP_REDEEM) {
            NoteRedeem r;
            if (DecodeNotePayload(tx.vchNotePayload, r)) { expectedNoteScript = NoteScriptForPubKey(r.vchHolderPubKey); fHaveExpectedNote = true; }
        } else if (tx.nNoteOp == NOTE_OP_CLAIM) {
            NoteClaim c;
            if (DecodeNotePayload(tx.vchNotePayload, c)) { expectedNoteScript = NoteScriptForPubKey(c.vchHolderPubKey); fHaveExpectedNote = true; }
        } else if (tx.nNoteOp == NOTE_OP_DEMAND) {
            NoteDemand d;
            if (DecodeNotePayload(tx.vchNotePayload, d)) { expectedNoteScript = NoteScriptForPubKey(d.vchHolderPubKey); fHaveExpectedNote = true; }
        }
    }

    // Same for a deposit TRANSFER/WITHDRAW/CLAIM: every spent receipt coin must be
    // a P2PKH to the declared sender/holder, so the payload sig authorizes THIS
    // receipt (ORIGINATE spends no receipts).
    CScript expectedDepositScript;
    bool fHaveExpectedDeposit = false;
    if (tx.nVersion == TRANSACTION_DEPOSIT_VERSION) {
        if (tx.nDepositOp == DEPOSIT_OP_TRANSFER) {
            DepositTransfer x;
            if (DecodeDepositPayload(tx.vchDepositPayload, x)) { expectedDepositScript = DepositScriptForPubKey(x.vchSenderPubKey); fHaveExpectedDeposit = true; }
        } else if (tx.nDepositOp == DEPOSIT_OP_WITHDRAW) {
            DepositWithdraw w;
            if (DecodeDepositPayload(tx.vchDepositPayload, w)) { expectedDepositScript = DepositScriptForPubKey(w.vchHolderPubKey); fHaveExpectedDeposit = true; }
        } else if (tx.nDepositOp == DEPOSIT_OP_CLAIM) {
            DepositClaim c;
            if (DecodeDepositPayload(tx.vchDepositPayload, c)) { expectedDepositScript = DepositScriptForPubKey(c.vchHolderPubKey); fHaveExpectedDeposit = true; }
        }
    }

    // For a pool op, every spent trader note coin / LP coin must be a P2PKH to
    // the declared creator/provider/trader (so the payload sig authorizes
    // THOSE coins). Decode once up front; the payload already passed shape.
    CScript expectedPoolScript;
    bool fHaveExpectedPool = false;
    if (tx.nVersion == TRANSACTION_POOL_VERSION) {
        if (tx.nPoolOp == POOL_OP_CREATE) {
            PoolCreate c;
            if (DecodePoolPayload(tx.vchPoolPayload, c)) { expectedPoolScript = PoolScriptForPubKey(c.vchCreatorPubKey); fHaveExpectedPool = true; }
        } else if (tx.nPoolOp == POOL_OP_ADD_LIQ) {
            PoolAddLiq a;
            if (DecodePoolPayload(tx.vchPoolPayload, a)) { expectedPoolScript = PoolScriptForPubKey(a.vchProviderPubKey); fHaveExpectedPool = true; }
        } else if (tx.nPoolOp == POOL_OP_REMOVE_LIQ) {
            PoolRemoveLiq r;
            if (DecodePoolPayload(tx.vchPoolPayload, r)) { expectedPoolScript = PoolScriptForPubKey(r.vchProviderPubKey); fHaveExpectedPool = true; }
        } else if (tx.nPoolOp == POOL_OP_SWAP) {
            PoolSwap s;
            if (DecodePoolPayload(tx.vchPoolPayload, s)) { expectedPoolScript = PoolScriptForPubKey(s.vchTraderPubKey); fHaveExpectedPool = true; }
        }
    }

    uint32_t nAssetIDFound = 0;
    CAmount nValueIn = 0;
    unsigned int nBillTitleIn = 0;
    unsigned int nBillEscrowIn = 0;
    uint32_t nBillIDIn = 0;
    unsigned int nHouseEscrowIn = 0;
    uint32_t nHouseIDIn = 0;
    unsigned int nNoteIn = 0;
    uint32_t nNoteHouseIn = 0;
    uint64_t nNoteUnitsIn = 0;
    uint32_t nDemandHeightIn = 0;
    unsigned int nDepositIn = 0;
    uint32_t nDepositHouseIn = 0;
    unsigned int nPoolNoteEscrowIn = 0;
    unsigned int nPoolBtxEscrowIn = 0;
    uint32_t nPoolEscrowIDIn = 0;
    uint64_t nPoolEscrowNoteUnitsIn = 0;
    unsigned int nLpIn = 0;
    uint32_t nLpPoolIDIn = 0;
    uint64_t nLpUnitsIn = 0;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const COutPoint &prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        // If prev is coinbase, check that it's matured
        if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
            return state.Invalid(false,
                REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }

        // Check for negative or overflow input values
        nValueIn += coin.out.nValue;
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
        }

        if (coin.nAssetID && nAssetIDFound && coin.nAssetID != nAssetIDFound)
            return state.DoS(10, false, REJECT_INVALID, "bad-txns-inputs-mixed-assets");

        nAssetIDFound = coin.nAssetID;

        // Bill spend guard: title / escrow coins are locked to their bill's
        // v11 operations; bill transactions cannot spend asset-colored coins
        // (keeps asset coloring out of AddCoins' bill branch)
        if (coin.fBill || coin.fBillEscrow) {
            if (tx.nVersion != TRANSACTION_BILL_VERSION)
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-spend-bill-coin");
            if (nBillIDIn != 0 && coin.nBillID != nBillIDIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-bill-inputs-mixed");

            nBillIDIn = coin.nBillID;
            if (coin.fBill)
                nBillTitleIn++;
            else
                nBillEscrowIn++;
        }
        else if (tx.nVersion == TRANSACTION_BILL_VERSION && coin.nAssetID) {
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-asset-input");
        }

        // House pledge guard: escrow coins are locked to their house's v12
        // RECLAIM op (wind-down / tail expiry release / insolvency residual
        // settle) and its v13 CLAIM op (the s7 pro-rata waterfall pays note
        // holders FROM the escrow pot). House txs cannot spend asset- or
        // bill-colored coins.
        if (coin.fHouseEscrow) {
            const bool fReclaim = tx.nVersion == TRANSACTION_HOUSE_VERSION && tx.nHouseOp == HOUSE_OP_RECLAIM;
            const bool fRelease = tx.nVersion == TRANSACTION_HOUSE_VERSION && tx.nHouseOp == HOUSE_OP_RELEASE;
            const bool fClaim = tx.nVersion == TRANSACTION_NOTE_VERSION && tx.nNoteOp == NOTE_OP_CLAIM;
            // A deposit CLAIM (v14) pays the subordinated tranche FROM the escrow
            // pot too, so it may spend house escrow (like the note CLAIM).
            const bool fDepClaim = tx.nVersion == TRANSACTION_DEPOSIT_VERSION && tx.nDepositOp == DEPOSIT_OP_CLAIM;
            if (!fReclaim && !fRelease && !fClaim && !fDepClaim)
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-spend-house-coin");
            if (nHouseIDIn != 0 && coin.nHouseID != nHouseIDIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-inputs-mixed");

            nHouseIDIn = coin.nHouseID;
            nHouseEscrowIn++;
        }
        else if (tx.nVersion == TRANSACTION_HOUSE_VERSION &&
                (coin.nAssetID || coin.fBill || coin.fBillEscrow)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-house-colored-input");
        }

        // Pool custody guard (Phase 3.7): the two canonical escrow coins are
        // locked to their pool's v15 ADD_LIQ / REMOVE_LIQ / SWAP, at FIXED
        // positions (vin[0] = the dual-tagged note side, vin[1] = the BTX
        // side) - a plain tx sweeping the anyone-can-spend script is a
        // reserve drain and rejected. CREATE spends no pool coins.
        if (coin.fPoolEscrow) {
            if (tx.nVersion != TRANSACTION_POOL_VERSION ||
                    (tx.nPoolOp != POOL_OP_ADD_LIQ && tx.nPoolOp != POOL_OP_REMOVE_LIQ &&
                     tx.nPoolOp != POOL_OP_SWAP && tx.nPoolOp != POOL_OP_RETIRE))
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-spend-pool-coin");
            if (nPoolEscrowIDIn != 0 && coin.nHouseID != nPoolEscrowIDIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-inputs-mixed");
            nPoolEscrowIDIn = coin.nHouseID;
            if (coin.fNote) {
                if (i != 0)
                    return state.DoS(100, false, REJECT_INVALID, "bad-pool-escrow-position");
                nPoolNoteEscrowIn++;
                nPoolEscrowNoteUnitsIn = coin.nNoteUnits;
            } else {
                if (i != 1)
                    return state.DoS(100, false, REJECT_INVALID, "bad-pool-escrow-position");
                nPoolBtxEscrowIn++;
            }
        }

        // LP-share guard: an LP coin is locked to its pool's v15 REMOVE_LIQ
        // (burn-only in v1) and must belong to the declared provider.
        if (coin.fLpShare) {
            if (tx.nVersion != TRANSACTION_POOL_VERSION || tx.nPoolOp != POOL_OP_REMOVE_LIQ)
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-spend-lp-coin");
            if (nLpPoolIDIn != 0 && coin.nHouseID != nLpPoolIDIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-lp-inputs-mixed");
            if (fHaveExpectedPool && coin.out.scriptPubKey != expectedPoolScript)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-lp-input-not-provider");
            nLpPoolIDIn = coin.nHouseID;
            nLpIn++;
            if (nLpIn > MAX_POOL_LP_INPUTS)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-lp-inputs-count");
            if (coin.nLpUnits > POOL_MAX_AMOUNT || nLpUnitsIn > POOL_MAX_AMOUNT - coin.nLpUnits)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-lp-units-overflow");
            nLpUnitsIn += coin.nLpUnits;
        }

        // Note guard: a note coin is locked to its house's v13 TRANSFER /
        // REDEEM / CLAIM (its base value is dust; the claim amount is
        // nNoteUnits) - or, since Phase 3.7, its pool's v15 CREATE / ADD_LIQ /
        // SWAP (the trader/provider side; pool custody coins take the
        // fPoolEscrow branch above instead). Any other spender - a plain tx,
        // a bill/house/asset tx, or a MINT - is a value/claim drain and
        // rejected. All note inputs must share one house; note txs cannot
        // spend asset/bill coins, and only CLAIM may spend house escrow
        // (checked above).
        if (coin.fNote && !coin.fPoolEscrow) {
            const bool fNoteOpOK = tx.nVersion == TRANSACTION_NOTE_VERSION &&
                    (tx.nNoteOp == NOTE_OP_TRANSFER || tx.nNoteOp == NOTE_OP_REDEEM ||
                     tx.nNoteOp == NOTE_OP_CLAIM || tx.nNoteOp == NOTE_OP_DEMAND);
            const bool fPoolOpOK = tx.nVersion == TRANSACTION_POOL_VERSION &&
                    (tx.nPoolOp == POOL_OP_CREATE || tx.nPoolOp == POOL_OP_ADD_LIQ ||
                     tx.nPoolOp == POOL_OP_SWAP);
            if (!fNoteOpOK && !fPoolOpOK)
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-spend-note-coin");
            if (nNoteHouseIn != 0 && coin.nHouseID != nNoteHouseIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-inputs-mixed-house");
            if (fHaveExpectedNote && coin.out.scriptPubKey != expectedNoteScript)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-input-not-holder");
            if (fPoolOpOK) {
                // Only UNDEMANDED notes may enter a pool (operator decision 4):
                // a demanded note's interest clock is a personal claim that
                // would break the fungibility of the pool's note reserve.
                if (coin.nDemandHeight != 0)
                    return state.DoS(100, false, REJECT_INVALID, "bad-pool-demanded-note");
                if (coin.out.scriptPubKey != expectedPoolScript)
                    return state.DoS(100, false, REJECT_INVALID, "bad-pool-note-input-not-owner");
            }
            // Every spent note must carry the SAME demand height: the clock is
            // a per-note property, and mixing demanded with undemanded (or
            // notes demanded at different dates) inside one op would make the
            // output tag - and the interest owed - ambiguous.
            if (nNoteIn > 0 && coin.nDemandHeight != nDemandHeightIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-inputs-mixed-demand");
            nDemandHeightIn = coin.nDemandHeight;
            nNoteHouseIn = coin.nHouseID;
            nNoteIn++;
            if (coin.nNoteUnits > (uint64_t)MAX_MONEY || nNoteUnitsIn > (uint64_t)MAX_MONEY - coin.nNoteUnits)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-units-overflow");
            nNoteUnitsIn += coin.nNoteUnits;
        }
        else if (tx.nVersion == TRANSACTION_NOTE_VERSION &&
                (coin.nAssetID || coin.fBill || coin.fBillEscrow ||
                 (coin.fHouseEscrow && tx.nNoteOp != NOTE_OP_CLAIM))) {
            return state.DoS(100, false, REJECT_INVALID, "bad-note-colored-input");
        }

        // Pool txs cannot spend asset/bill/house-escrow/deposit-colored coins:
        // the asset branch of AddCoins would mis-tag pool outputs, and none of
        // those instruments has any business inside a swap. (Notes and pool
        // coins are handled by their own branches above.)
        if (tx.nVersion == TRANSACTION_POOL_VERSION &&
                (coin.nAssetID || coin.fBill || coin.fBillEscrow || coin.fHouseEscrow || coin.fDeposit)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-colored-input");
        }

        // Deposit-receipt guard: a receipt coin (dust base value; the claim is
        // the tagged principal + accrued) is locked to its house's v14 TRANSFER /
        // WITHDRAW / CLAIM. Any other spender - a plain tx, a bill/house/note/asset
        // tx, or an ORIGINATE - is a claim drain and rejected. All receipt inputs
        // must share one house; deposit txs cannot spend asset/bill/note coins,
        // and only a CLAIM may spend house escrow (checked above).
        if (coin.fDeposit) {
            if (tx.nVersion != TRANSACTION_DEPOSIT_VERSION ||
                    (tx.nDepositOp != DEPOSIT_OP_TRANSFER && tx.nDepositOp != DEPOSIT_OP_WITHDRAW &&
                     tx.nDepositOp != DEPOSIT_OP_CLAIM))
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-spend-deposit-coin");
            if (nDepositHouseIn != 0 && coin.nHouseID != nDepositHouseIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-inputs-mixed-house");
            if (fHaveExpectedDeposit && coin.out.scriptPubKey != expectedDepositScript)
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-input-not-holder");
            nDepositHouseIn = coin.nHouseID;
            nDepositIn++;
        }
        else if (tx.nVersion == TRANSACTION_DEPOSIT_VERSION &&
                (coin.nAssetID || coin.fBill || coin.fBillEscrow || coin.fNote ||
                 (coin.fHouseEscrow && tx.nDepositOp != DEPOSIT_OP_CLAIM))) {
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-colored-input");
        }
    }

    if (tx.nVersion == TRANSACTION_BILL_VERSION) {
        // Structure per op: ISSUE spends only plain coins; ENDORSE spends
        // exactly its bill's title; RETIRE / CLAIM spend exactly its bill's
        // escrow. The payload's nBillID must match the spent coin's tag.
        uint32_t nBillIDPayload = 0;
        if (tx.nBillOp == BILL_OP_ENDORSE) {
            BillEndorse endorse;
            if (!DecodeBillPayload(tx.vchBillPayload, endorse))
                return state.DoS(100, false, REJECT_INVALID, "bad-bill-endorse-payload");
            nBillIDPayload = endorse.nBillID;
            if (nBillTitleIn != 1 || nBillEscrowIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-bill-endorse-inputs");
        }
        else if (tx.nBillOp == BILL_OP_RETIRE) {
            BillRetire retire;
            if (!DecodeBillPayload(tx.vchBillPayload, retire))
                return state.DoS(100, false, REJECT_INVALID, "bad-bill-retire-payload");
            nBillIDPayload = retire.nBillID;
            if (nBillTitleIn != 0 || nBillEscrowIn != 1)
                return state.DoS(100, false, REJECT_INVALID, "bad-bill-retire-inputs");
        }
        else if (tx.nBillOp == BILL_OP_CLAIM) {
            BillClaim claim;
            if (!DecodeBillPayload(tx.vchBillPayload, claim))
                return state.DoS(100, false, REJECT_INVALID, "bad-bill-claim-payload");
            nBillIDPayload = claim.nBillID;
            if (nBillTitleIn != 0 || nBillEscrowIn != 1)
                return state.DoS(100, false, REJECT_INVALID, "bad-bill-claim-inputs");
        }
        else {
            // ISSUE
            if (nBillTitleIn != 0 || nBillEscrowIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-inputs");
        }

        if (nBillIDPayload != nBillIDIn)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-input-id-mismatch");
    }

    if (tx.nVersion == TRANSACTION_HOUSE_VERSION) {
        // Structure per op: RECLAIM spends >= 1 of its house's pledge coins
        // (plus plain fee inputs); every other house op spends plain coins
        // only. The payload's nHouseID must match the spent coins' tag; the
        // partner-index ownership check is contextual (CheckHouseOperation).
        if (tx.nHouseOp == HOUSE_OP_RECLAIM) {
            HouseReclaim rec;
            if (!DecodeHousePayload(tx.vchHousePayload, rec))
                return state.DoS(100, false, REJECT_INVALID, "bad-house-reclaim-payload");
            if (nHouseEscrowIn == 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-reclaim-inputs");
            if (rec.nHouseID != nHouseIDIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-input-id-mismatch");
        } else if (tx.nHouseOp == HOUSE_OP_RELEASE) {
            HouseRelease rel;
            if (!DecodeHousePayload(tx.vchHousePayload, rel))
                return state.DoS(100, false, REJECT_INVALID, "bad-house-release-payload");
            if (nHouseEscrowIn == 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-release-inputs");
            if (rel.nHouseID != nHouseIDIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-input-id-mismatch");
        } else {
            if (nHouseEscrowIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-op-spends-escrow");
        }
    }

    if (tx.nVersion == TRANSACTION_NOTE_VERSION) {
        // Structure + unit accounting (cheap). The ECDSA auth, the house
        // status/cap, and the nMintedUnits delta are contextual (CheckNoteOperation).
        if (tx.nNoteOp == NOTE_OP_MINT) {
            // A mint creates supply from plain fee inputs; it must not spend notes.
            if (nNoteIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-spends-note");
        }
        else if (tx.nNoteOp == NOTE_OP_TRANSFER) {
            NoteTransfer x;
            if (!DecodeNotePayload(tx.vchNotePayload, x))
                return state.DoS(100, false, REJECT_INVALID, "bad-note-transfer-payload");
            if (nNoteIn == 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-transfer-inputs");
            if (x.nHouseID != nNoteHouseIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-input-house-mismatch");
            // The payload's demand height must be the one the spent notes
            // actually carry: AddCoins tags the new outputs from the PAYLOAD
            // (self-contained, so connect == rollforward), so a lie here would
            // mint or destroy an interest claim.
            if (x.nDemandHeight != nDemandHeightIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-transfer-demand-mismatch");
            // Conservation: no minting via transfer. Out-units == in-units.
            uint64_t out = 0;
            if (!SumNoteUnits(x.vUnits, out))
                return state.DoS(100, false, REJECT_INVALID, "bad-note-transfer-units");
            if (out != nNoteUnitsIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-transfer-conservation");
        }
        else if (tx.nNoteOp == NOTE_OP_DEMAND) {
            NoteDemand d;
            if (!DecodeNotePayload(tx.vchNotePayload, d))
                return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-payload");
            if (nNoteIn == 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-inputs");
            if (d.nHouseID != nNoteHouseIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-input-house-mismatch");
            // Demanding an already-demanded note would silently RESET its
            // clock, throwing away accrued interest.
            if (nDemandHeightIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-already-demanded");
            if (nHouseEscrowIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-op-spends-escrow");
            // The notes are re-issued, not surrendered: units conserved exactly.
            uint64_t out = 0;
            if (!SumNoteUnits(d.vUnits, out))
                return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-units");
            if (out != nNoteUnitsIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-conservation");
        }
        else if (tx.nNoteOp == NOTE_OP_REDEEM) {
            NoteRedeem r;
            if (!DecodeNotePayload(tx.vchNotePayload, r))
                return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-payload");
            if (nNoteIn == 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-inputs");
            if (r.nHouseID != nNoteHouseIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-input-house-mismatch");
            // A redeem never touches escrow - the house pays from its own till
            if (nHouseEscrowIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-spends-escrow");
            // The U-unit burn = nNoteUnitsIn; the holder authorizes the exact
            // outputs by signing hashOutputs (CheckNoteOperation), so the payout
            // amount is their signed choice - no separate consensus floor.
        }
        else if (tx.nNoteOp == NOTE_OP_CLAIM) {
            NoteClaim c;
            if (!DecodeNotePayload(tx.vchNotePayload, c))
                return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-payload");
            if (nNoteIn == 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-inputs");
            if (c.nHouseID != nNoteHouseIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-input-house-mismatch");
            // Any escrow spent must belong to the SAME house being claimed
            if (nHouseEscrowIn != 0 && nHouseIDIn != c.nHouseID)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-escrow-mismatch");
            // The pro-rata entitlement bound (escrowIn - escrowChange <=
            // min(U, U*pot/units)) is contextual - it needs the insolvency
            // snapshot from the house record. (MINT / TRANSFER spending
            // escrow is already rejected by the coin-loop guard above.)
        }
    }

    if (tx.nVersion == TRANSACTION_DEPOSIT_VERSION) {
        // Structure per op. The ECDSA auth, the house status/cap, the maturity /
        // interest-floor / subordinated-entitlement checks are contextual
        // (CheckDepositOperation).
        if (tx.nDepositOp == DEPOSIT_OP_ORIGINATE) {
            // Originates receipts from plain fee/funding inputs; spends no receipt
            // and no escrow.
            if (nDepositIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-originate-spends-receipt");
            if (nHouseEscrowIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-op-spends-escrow");
        }
        else if (tx.nDepositOp == DEPOSIT_OP_TRANSFER) {
            DepositTransfer x;
            if (!DecodeDepositPayload(tx.vchDepositPayload, x))
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-transfer-payload");
            // Exactly one WHOLE receipt reassigned (no split/merge).
            if (nDepositIn != 1)
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-transfer-inputs");
            if (x.nHouseID != nDepositHouseIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-input-house-mismatch");
            if (nHouseEscrowIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-op-spends-escrow");
        }
        else if (tx.nDepositOp == DEPOSIT_OP_WITHDRAW) {
            DepositWithdraw w;
            if (!DecodeDepositPayload(tx.vchDepositPayload, w))
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-withdraw-payload");
            // Burns exactly one receipt; the house funds the payout from its own
            // plain inputs (never escrow - a term claim is not a waterfall claim).
            if (nDepositIn != 1)
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-withdraw-inputs");
            if (w.nHouseID != nDepositHouseIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-input-house-mismatch");
            if (nHouseEscrowIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-op-spends-escrow");
        }
        else if (tx.nDepositOp == DEPOSIT_OP_CLAIM) {
            DepositClaim c;
            if (!DecodeDepositPayload(tx.vchDepositPayload, c))
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-claim-payload");
            // Burns exactly one receipt and pays the subordinated tranche from the
            // escrow pot; any escrow spent must belong to the same house.
            if (nDepositIn != 1)
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-claim-inputs");
            if (c.nHouseID != nDepositHouseIn)
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-input-house-mismatch");
            if (nHouseEscrowIn != 0 && nHouseIDIn != c.nHouseID)
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-claim-escrow-mismatch");
        }
    }

    if (tx.nVersion == TRANSACTION_POOL_VERSION) {
        // Structure + conservation per op (cheap; the ECDSA auth, the priors-
        // vs-CPool equality, the swap formula and the house checks are
        // contextual in CheckPoolOperation). The load-bearing invariant here:
        // NO pool op mints or burns note-units - every unit entering or
        // leaving custody is accounted against the trader/provider inputs.
        if (tx.nPoolOp == POOL_OP_CREATE) {
            PoolCreate create;
            if (!DecodePoolPayload(tx.vchPoolPayload, create))
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-create-payload");
            // A CREATE builds the escrow pair fresh: no pool coins, no LP coins.
            if (nPoolNoteEscrowIn != 0 || nPoolBtxEscrowIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-create-spends-escrow");
            if (nLpIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-create-spends-lp");
            // Conservation: the creator's notes fund the seed exactly.
            if (nNoteIn == 0 || nNoteHouseIn != create.nPoolID)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-note-house-mismatch");
            if (nNoteUnitsIn != create.nInitNoteUnits + create.nNoteChangeUnits)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-create-conservation");
        }
        else if (tx.nPoolOp == POOL_OP_ADD_LIQ) {
            PoolAddLiq add;
            if (!DecodePoolPayload(tx.vchPoolPayload, add))
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-add-payload");
            if (nPoolNoteEscrowIn != 1 || nPoolBtxEscrowIn != 1)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-escrow-inputs");
            if (nPoolEscrowIDIn != add.nPoolID)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-input-id-mismatch");
            // The spent custody coin must carry exactly the declared prior X
            // (belt-and-braces with the contextual CPool equality).
            if (nPoolEscrowNoteUnitsIn != add.nPriorNoteReserve)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-prior-mismatch");
            if (nLpIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-add-spends-lp");
            if (nNoteIn == 0 || nNoteHouseIn != add.nPoolID)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-note-house-mismatch");
            if (nNoteUnitsIn != add.nAddNoteUnits + add.nNoteChangeUnits)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-add-conservation");
        }
        else if (tx.nPoolOp == POOL_OP_REMOVE_LIQ) {
            PoolRemoveLiq rem;
            if (!DecodePoolPayload(tx.vchPoolPayload, rem))
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-remove-payload");
            if (nPoolNoteEscrowIn != 1 || nPoolBtxEscrowIn != 1)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-escrow-inputs");
            if (nPoolEscrowIDIn != rem.nPoolID)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-input-id-mismatch");
            if (nPoolEscrowNoteUnitsIn != rem.nPriorNoteReserve)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-prior-mismatch");
            // A remove burns LP shares against custody only - no trader notes.
            if (nNoteIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-remove-note-inputs");
            if (nLpIn == 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-remove-lp-inputs");
            if (nLpPoolIDIn != rem.nPoolID)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-lp-id-mismatch");
            // LP conservation: burned + change == spent (no share minting).
            if (nLpUnitsIn != rem.nBurnLp + rem.nLpChangeUnits)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-remove-lp-conservation");
        }
        else if (tx.nPoolOp == POOL_OP_SWAP) {
            PoolSwap swap;
            if (!DecodePoolPayload(tx.vchPoolPayload, swap))
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-payload");
            if (nPoolNoteEscrowIn != 1 || nPoolBtxEscrowIn != 1)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-escrow-inputs");
            if (nPoolEscrowIDIn != swap.nPoolID)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-input-id-mismatch");
            if (nPoolEscrowNoteUnitsIn != swap.nPriorNoteReserve)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-prior-mismatch");
            if (nLpIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-spends-lp");
            if (swap.nDirection == POOL_SWAP_NOTE_TO_BTX) {
                // The trader's notes fund the in-side exactly.
                if (nNoteIn == 0 || nNoteHouseIn != swap.nPoolID)
                    return state.DoS(100, false, REJECT_INVALID, "bad-pool-note-house-mismatch");
                if (nNoteUnitsIn != swap.nAmountIn + swap.nNoteChangeUnits)
                    return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-conservation");
            } else {
                // BTX->note: the trader funds with plain sats only.
                if (nNoteIn != 0)
                    return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-note-inputs");
            }
        }
        else if (tx.nPoolOp == POOL_OP_RETIRE) {
            PoolRetire ret;
            if (!DecodePoolPayload(tx.vchPoolPayload, ret))
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-payload");
            // RETIRE spends the custody pair ONLY: no LP inputs (the fLpShare
            // guard already rejects them - op 5 is not in its op set), no trader
            // notes (the fNote guard rejects them likewise). The spent note-side
            // custody coin must carry exactly the declared prior X (belt-and-
            // braces with the contextual CPool equality).
            if (nPoolNoteEscrowIn != 1 || nPoolBtxEscrowIn != 1)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-escrow-inputs");
            if (nPoolEscrowIDIn != ret.nPoolID)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-input-id-mismatch");
            if (nPoolEscrowNoteUnitsIn != ret.nPriorNoteReserve)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-prior-mismatch");
            if (nLpIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-spends-lp");
            if (nNoteIn != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-note-inputs");
        }
    }

    const CAmount value_out = tx.GetValueOut();
    if (nValueIn < value_out) {
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-in-belowout", false,
            strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(value_out)));
    }

    // Tally transaction fees
    const CAmount txfee_aux = nValueIn - value_out;
    if (!MoneyRange(txfee_aux)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");
    }

    txfee = txfee_aux;
    return true;
}
