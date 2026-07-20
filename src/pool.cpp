// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pool.h>

#include <coins.h>
#include <consensus/validation.h>
#include <hash.h>
#include <pubkey.h>
#include <script/standard.h>
#include <streams.h>
#include <version.h>

uint256 PoolEscrowTag(uint32_t nPoolID)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankPoolEscrow");
    ss << nPoolID;
    return ss.GetHash();
}

CScript PoolEscrowScript(uint32_t nPoolID)
{
    const uint256 tag = PoolEscrowTag(nPoolID);
    return CScript() << std::vector<unsigned char>(tag.begin(), tag.end()) << OP_DROP << OP_TRUE;
}

bool IsPoolEscrowScript(const CScript& script)
{
    // <32-byte push> OP_DROP OP_TRUE - structurally identical to house/bill
    // escrow; the domain-separated tag keeps the actual scripts disjoint and
    // the fPoolEscrow coin tag is what the spend guard enforces.
    return script.size() == 35 && script[0] == 0x20 &&
           script[33] == OP_DROP && script[34] == OP_TRUE;
}

CScript PoolScriptForPubKey(const std::vector<unsigned char>& vchPubKey)
{
    CPubKey pubkey(vchPubKey);
    return GetScriptForDestination(pubkey.GetID());
}

uint256 PoolHashPrevouts(const CTransaction& tx)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (const CTxIn& in : tx.vin)
        ss << in.prevout;
    return ss.GetHash();
}

uint256 PoolCreateSigHash(uint32_t nPoolID, uint32_t nFeeBps, uint64_t nInitNoteUnits,
                          int64_t amountInitBtx, uint64_t nNoteChangeUnits,
                          const uint256& hashPrevouts, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankPool/create");
    ss << nPoolID;
    ss << nFeeBps;
    ss << nInitNoteUnits;
    ss << amountInitBtx;
    ss << nNoteChangeUnits;
    ss << hashPrevouts;   // tx-unique -> neither the charter nor the seed is replayable
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 PoolAddLiqSigHash(const PoolAddLiq& add, const uint256& hashPrevouts, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankPool/add");
    ss << add.nPoolID;
    ss << add.nPriorNoteReserve;
    ss << add.amountPriorBtxReserve;
    ss << add.nPriorLpSupply;
    ss << add.nAddNoteUnits;
    ss << add.amountAddBtx;
    ss << add.nLpMinted;
    ss << add.nNoteChangeUnits;
    ss << hashPrevouts;
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 PoolRemoveLiqSigHash(const PoolRemoveLiq& rem, const uint256& hashPrevouts, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankPool/remove");
    ss << rem.nPoolID;
    ss << rem.nPriorNoteReserve;
    ss << rem.amountPriorBtxReserve;
    ss << rem.nPriorLpSupply;
    ss << rem.nBurnLp;
    ss << rem.nNoteOut;
    ss << rem.amountBtxOut;
    ss << rem.nLpChangeUnits;
    ss << hashPrevouts;
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 PoolSwapSigHash(const PoolSwap& swap, const uint256& hashPrevouts, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankPool/swap");
    ss << swap.nPoolID;
    ss << swap.nPriorNoteReserve;
    ss << swap.amountPriorBtxReserve;
    ss << swap.nPriorLpSupply;
    ss << swap.nDirection;
    ss << swap.nAmountIn;
    ss << swap.nMinOut;
    ss << swap.nAmountOut;
    ss << swap.nNoteChangeUnits;
    ss << hashPrevouts;
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 PoolRetireSigHash(const PoolRetire& ret, const uint256& hashPrevouts, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankPool/retire");
    ss << ret.nPoolID;
    ss << ret.nPriorNoteReserve;
    ss << ret.amountPriorBtxReserve;
    ss << ret.nPriorLpSupply;
    ss << ret.nFeeBps;
    ss << ret.nCreateHeight;
    ss << ret.nTriggerPartnerIndex;   // 0 on the M-of-N path; the trigger signer on the insolvency path
    ss << hashPrevouts;
    ss << hashOutputs;                 // pins the forced floor-BTX payout (vout[0]) and the whole output set
    return ss.GetHash();
}

template <typename T>
bool DecodePoolPayload(const std::vector<unsigned char>& vch, T& payload)
{
    try {
        CDataStream ss(vch, SER_NETWORK, PROTOCOL_VERSION);
        ss >> payload;
        if (!ss.empty())
            return false;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

template bool DecodePoolPayload<PoolCreate>(const std::vector<unsigned char>&, PoolCreate&);
template bool DecodePoolPayload<PoolAddLiq>(const std::vector<unsigned char>&, PoolAddLiq&);
template bool DecodePoolPayload<PoolRemoveLiq>(const std::vector<unsigned char>&, PoolRemoveLiq&);
template bool DecodePoolPayload<PoolSwap>(const std::vector<unsigned char>&, PoolSwap&);
template bool DecodePoolPayload<PoolRetire>(const std::vector<unsigned char>&, PoolRetire&);

void ApplyPoolCoinTags(const CTransaction& tx, uint32_t n, Coin& coin)
{
    if (tx.nVersion != TRANSACTION_POOL_VERSION)
        return;

    if (tx.nPoolOp == POOL_OP_CREATE) {
        PoolCreate create;
        if (!DecodePoolPayload(tx.vchPoolPayload, create))
            return;
        if (n == 0) {
            coin.SetNote(create.nPoolID, create.nInitNoteUnits);
            coin.SetPoolEscrow(create.nPoolID);
        } else if (n == 1) {
            coin.SetPoolEscrow(create.nPoolID);
        } else if (n == 2) {
            uint64_t toCreator = 0, supply0 = 0;
            if (PoolLpMintInitial(create.nInitNoteUnits, create.amountInitBtx, toCreator, supply0))
                coin.SetLpShare(create.nPoolID, toCreator);
        } else if (n == 3 && create.nNoteChangeUnits > 0) {
            coin.SetNote(create.nPoolID, create.nNoteChangeUnits);
        }
    }
    else if (tx.nPoolOp == POOL_OP_ADD_LIQ) {
        PoolAddLiq add;
        if (!DecodePoolPayload(tx.vchPoolPayload, add))
            return;
        if (n == 0) {
            coin.SetNote(add.nPoolID, add.nPriorNoteReserve + add.nAddNoteUnits);
            coin.SetPoolEscrow(add.nPoolID);
        } else if (n == 1) {
            coin.SetPoolEscrow(add.nPoolID);
        } else if (n == 2) {
            coin.SetLpShare(add.nPoolID, add.nLpMinted);
        } else if (n == 3 && add.nNoteChangeUnits > 0) {
            coin.SetNote(add.nPoolID, add.nNoteChangeUnits);
        }
    }
    else if (tx.nPoolOp == POOL_OP_REMOVE_LIQ) {
        PoolRemoveLiq rem;
        if (!DecodePoolPayload(tx.vchPoolPayload, rem))
            return;
        if (rem.nNoteOut > rem.nPriorNoteReserve)
            return;   // shape-rejected upstream; never tag from inconsistent data
        if (n == 0) {
            coin.SetNote(rem.nPoolID, rem.nPriorNoteReserve - rem.nNoteOut);
            coin.SetPoolEscrow(rem.nPoolID);
            return;
        }
        if (n == 1) {
            coin.SetPoolEscrow(rem.nPoolID);
            return;
        }
        // Payouts pack in order [note (iff nNoteOut>0), BTX (iff amountBtxOut>0),
        // LP change (iff nLpChangeUnits>0)]: a side that floors to 0 is OMITTED
        // (zero-side companion), so the LP-change index shifts. Only the note
        // payout (fNote) and the LP change (fLpShare) are tagged; the BTX payout
        // is plain. Both-zero is impossible (shape/redeem reject it).
        uint32_t idx = 2;
        if (rem.nNoteOut > 0) {
            if (n == idx) { coin.SetNote(rem.nPoolID, rem.nNoteOut); return; }
            idx++;
        }
        if (rem.amountBtxOut > 0)
            idx++;   // plain BTX payout - not tagged
        if (rem.nLpChangeUnits > 0 && n == idx)
            coin.SetLpShare(rem.nPoolID, rem.nLpChangeUnits);
    }
    else if (tx.nPoolOp == POOL_OP_SWAP) {
        PoolSwap swap;
        if (!DecodePoolPayload(tx.vchPoolPayload, swap))
            return;
        if (swap.nDirection == POOL_SWAP_NOTE_TO_BTX) {
            if (n == 0) {
                coin.SetNote(swap.nPoolID, swap.nPriorNoteReserve + swap.nAmountIn);
                coin.SetPoolEscrow(swap.nPoolID);
            } else if (n == 1) {
                coin.SetPoolEscrow(swap.nPoolID);
            } else if (n == 3 && swap.nNoteChangeUnits > 0) {
                coin.SetNote(swap.nPoolID, swap.nNoteChangeUnits);
            }
            // n == 2 is the plain BTX payout - untagged.
        } else if (swap.nDirection == POOL_SWAP_BTX_TO_NOTE) {
            if (swap.nAmountOut > swap.nPriorNoteReserve)
                return;   // shape-rejected upstream
            if (n == 0) {
                coin.SetNote(swap.nPoolID, swap.nPriorNoteReserve - swap.nAmountOut);
                coin.SetPoolEscrow(swap.nPoolID);
            } else if (n == 1) {
                coin.SetPoolEscrow(swap.nPoolID);
            } else if (n == 2) {
                coin.SetNote(swap.nPoolID, swap.nAmountOut);
            }
        }
    }
    else if (tx.nPoolOp == POOL_OP_RETIRE) {
        // Terminal op: the custody pair is consumed, the residual note-units are
        // burned from the house, and the floor BTX is force-paid to a plain
        // P2PKH. NOTHING is re-issued, so EVERY output is plain - explicit no-op
        // so a reader sees op 5 was handled here, not forgotten.
    }
}

static bool IsValidPoolPubKey(const std::vector<unsigned char>& vch)
{
    if (vch.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE)
        return false;
    CPubKey pubkey(vch);
    return pubkey.IsFullyValid();
}

static bool IsPoolSigShape(const std::vector<unsigned char>& vchSig)
{
    return !vchSig.empty() && vchSig.size() <= 80;
}

/** vout[0] = note-side escrow (POOL_DUST_VALUE), vout[1] = BTX-side escrow
 * (amountBtxExpected) - both must pay the pool's exact escrow script. The
 * expected value derives from the payload alone, so this is context-free. */
static bool CheckPoolEscrowPair(const CTransaction& tx, uint32_t nPoolID,
                                CAmount amountBtxExpected, CValidationState& state)
{
    if (tx.vout.size() < 3)
        return state.DoS(100, false, REJECT_INVALID, "bad-pool-vout-size");
    if (amountBtxExpected <= 0 || (uint64_t)amountBtxExpected > POOL_MAX_AMOUNT)
        return state.DoS(100, false, REJECT_INVALID, "bad-pool-escrow-value");
    const CScript scriptEscrow = PoolEscrowScript(nPoolID);
    if (tx.vout[0].scriptPubKey != scriptEscrow || tx.vout[0].nValue != POOL_DUST_VALUE)
        return state.DoS(100, false, REJECT_INVALID, "bad-pool-note-escrow-output");
    if (tx.vout[1].scriptPubKey != scriptEscrow || tx.vout[1].nValue != amountBtxExpected)
        return state.DoS(100, false, REJECT_INVALID, "bad-pool-btx-escrow-output");
    return true;
}

/** A dust-valued P2PKH output paying the DECLARED pubkey (LP coins, note
 * payouts, note/LP change - every tagged non-escrow pool output). */
static bool IsPoolDustToPubKey(const CTxOut& out, const std::vector<unsigned char>& vchPubKey)
{
    return out.nValue == POOL_DUST_VALUE && out.scriptPubKey == PoolScriptForPubKey(vchPubKey);
}

/** A standard P2PKH script shape (OP_DUP OP_HASH160 <20> OP_EQUALVERIFY
 * OP_CHECKSIG). The RETIRE floor-BTX payout must be P2PKH at shape level; its
 * EXACT destination P2PKH(house.vchRedemptionDestPK) is pinned contextually. */
static bool IsPoolP2PKHShape(const CScript& script)
{
    return script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 &&
           script[2] == 0x14 && script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG;
}

bool CheckPoolTransactionShape(const CTransaction& tx, CValidationState& state)
{
    if (tx.IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-pool-coinbase");
    if (tx.nPoolOp < POOL_OP_CREATE || tx.nPoolOp > POOL_OP_RETIRE)
        return state.DoS(100, false, REJECT_INVALID, "bad-pool-op");
    if (tx.vchPoolPayload.size() > MAX_POOL_PAYLOAD)
        return state.DoS(100, false, REJECT_INVALID, "bad-pool-payload-oversize");

    if (tx.nPoolOp == POOL_OP_CREATE) {
        PoolCreate create;
        if (!DecodePoolPayload(tx.vchPoolPayload, create))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-create-payload");
        if (create.nPoolID == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-id");
        if (create.nFeeBps < POOL_FEE_BPS_MIN || create.nFeeBps > POOL_FEE_BPS_MAX)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-create-fee");
        // The seed must clear the MIN_LIQUIDITY floor (also bounds both sides).
        uint64_t toCreator = 0, supply0 = 0;
        if (!PoolLpMintInitial(create.nInitNoteUnits, create.amountInitBtx, toCreator, supply0))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-create-seed");
        if (create.nNoteChangeUnits > POOL_MAX_AMOUNT)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-note-change");
        if (!IsValidPoolPubKey(create.vchCreatorPubKey) || !IsPoolSigShape(create.vchCreatorSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-create-sig-shape");
        // Approver arrays: non-empty, strictly ascending, sized. Ranges vs the
        // partner set + the ECDSA are contextual.
        if (create.vApproverIndex.empty() || create.vApproverIndex.size() != create.vApproverSig.size())
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-create-approvers");
        for (size_t i = 0; i < create.vApproverIndex.size(); i++) {
            if (i > 0 && create.vApproverIndex[i] <= create.vApproverIndex[i - 1])
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-create-approvers");
            if (!IsPoolSigShape(create.vApproverSig[i]))
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-create-approvers");
        }
        if (!CheckPoolEscrowPair(tx, create.nPoolID, create.amountInitBtx, state))
            return false;
        if (!IsPoolDustToPubKey(tx.vout[2], create.vchCreatorPubKey))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-lp-output");
        if (create.nNoteChangeUnits > 0 &&
                (tx.vout.size() < 4 || !IsPoolDustToPubKey(tx.vout[3], create.vchCreatorPubKey)))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-note-change-output");
    }
    else if (tx.nPoolOp == POOL_OP_ADD_LIQ) {
        PoolAddLiq add;
        if (!DecodePoolPayload(tx.vchPoolPayload, add))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-add-payload");
        if (add.nPoolID == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-id");
        // The min-rule formula is payload-pure: verify it context-free (it also
        // bounds the priors, the adds and the post-add envelope).
        uint64_t minted = 0;
        if (!PoolLpMintProportional(add.nAddNoteUnits, add.amountAddBtx,
                                    add.nPriorNoteReserve, add.amountPriorBtxReserve, add.nPriorLpSupply,
                                    minted) || minted != add.nLpMinted)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-add-amounts");
        if (add.nPriorLpSupply < POOL_MIN_LIQUIDITY)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-add-amounts");
        if (add.nNoteChangeUnits > POOL_MAX_AMOUNT)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-note-change");
        if (!IsValidPoolPubKey(add.vchProviderPubKey) || !IsPoolSigShape(add.vchProviderSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-add-sig-shape");
        if (tx.vin.size() < 3)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-vin-size");
        if (!CheckPoolEscrowPair(tx, add.nPoolID, add.amountPriorBtxReserve + add.amountAddBtx, state))
            return false;
        if (!IsPoolDustToPubKey(tx.vout[2], add.vchProviderPubKey))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-lp-output");
        if (add.nNoteChangeUnits > 0 &&
                (tx.vout.size() < 4 || !IsPoolDustToPubKey(tx.vout[3], add.vchProviderPubKey)))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-note-change-output");
    }
    else if (tx.nPoolOp == POOL_OP_REMOVE_LIQ) {
        PoolRemoveLiq rem;
        if (!DecodePoolPayload(tx.vchPoolPayload, rem))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-remove-payload");
        if (rem.nPoolID == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-id");
        // The redeem formula is payload-pure: verify both payouts context-free
        // (covers the MIN_LIQUIDITY floor and the no-dust-burn rule).
        uint64_t noteOut = 0;
        CAmount btxOut = 0;
        if (!PoolLpRedeemAmounts(rem.nBurnLp, rem.nPriorNoteReserve, rem.amountPriorBtxReserve,
                                 rem.nPriorLpSupply, noteOut, btxOut) ||
                noteOut != rem.nNoteOut || btxOut != rem.amountBtxOut)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-remove-amounts");
        if (rem.nLpChangeUnits > POOL_MAX_AMOUNT)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-lp-change");
        if (!IsValidPoolPubKey(rem.vchProviderPubKey) || !IsPoolSigShape(rem.vchProviderSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-remove-sig-shape");
        if (tx.vin.size() < 3)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-vin-size");
        if (!CheckPoolEscrowPair(tx, rem.nPoolID, rem.amountPriorBtxReserve - rem.amountBtxOut, state))
            return false;
        // Payouts pack in order [note (iff nNoteOut>0), BTX (iff amountBtxOut>0),
        // LP change (iff nLpChangeUnits>0)] after the vout[0/1] escrow pair. A
        // side that floors to 0 is OMITTED (zero-side companion), so downstream
        // indices shift; PoolLpRedeemAmounts already guaranteed not-both-zero.
        size_t idx = 2;
        if (rem.nNoteOut > 0) {
            if (tx.vout.size() <= idx || !IsPoolDustToPubKey(tx.vout[idx], rem.vchProviderPubKey))
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-note-payout");
            idx++;
        }
        if (rem.amountBtxOut > 0) {
            if (tx.vout.size() <= idx || tx.vout[idx].nValue != rem.amountBtxOut ||
                    tx.vout[idx].scriptPubKey != PoolScriptForPubKey(rem.vchProviderPubKey))
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-btx-payout");
            idx++;
        }
        if (rem.nLpChangeUnits > 0) {
            if (tx.vout.size() <= idx || !IsPoolDustToPubKey(tx.vout[idx], rem.vchProviderPubKey))
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-lp-change-output");
            idx++;
        }
    }
    else if (tx.nPoolOp == POOL_OP_SWAP) {
        PoolSwap swap;
        if (!DecodePoolPayload(tx.vchPoolPayload, swap))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-payload");
        if (swap.nPoolID == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-id");
        if (swap.nDirection != POOL_SWAP_NOTE_TO_BTX && swap.nDirection != POOL_SWAP_BTX_TO_NOTE)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-direction");
        // Bounds only: nAmountOut vs the x*y=k formula needs the pool's fee
        // (DB state), so the formula equality is contextual.
        if (swap.nAmountIn == 0 || swap.nAmountIn > POOL_MAX_AMOUNT ||
                swap.nAmountOut == 0 || swap.nAmountOut > POOL_MAX_AMOUNT ||
                swap.nMinOut > POOL_MAX_AMOUNT ||
                swap.nPriorNoteReserve == 0 || swap.nPriorNoteReserve > POOL_MAX_AMOUNT ||
                swap.amountPriorBtxReserve <= 0 || (uint64_t)swap.amountPriorBtxReserve > POOL_MAX_AMOUNT ||
                swap.nPriorLpSupply < POOL_MIN_LIQUIDITY || swap.nPriorLpSupply > POOL_MAX_AMOUNT)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-amounts");
        if (swap.nAmountOut < swap.nMinOut)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-min-out");
        if (!IsValidPoolPubKey(swap.vchTraderPubKey) || !IsPoolSigShape(swap.vchTraderSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-sig-shape");
        if (tx.vin.size() < 3)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-vin-size");

        if (swap.nDirection == POOL_SWAP_NOTE_TO_BTX) {
            if (swap.nAmountOut >= (uint64_t)swap.amountPriorBtxReserve)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-amounts");
            if ((unsigned __int128)swap.nPriorNoteReserve + swap.nAmountIn > (unsigned __int128)POOL_MAX_AMOUNT)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-amounts");
            if (swap.nNoteChangeUnits > POOL_MAX_AMOUNT)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-note-change");
            if (!CheckPoolEscrowPair(tx, swap.nPoolID, swap.amountPriorBtxReserve - (CAmount)swap.nAmountOut, state))
                return false;
            if (tx.vout[2].nValue != (CAmount)swap.nAmountOut ||
                    tx.vout[2].scriptPubKey != PoolScriptForPubKey(swap.vchTraderPubKey))
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-btx-payout");
            if (swap.nNoteChangeUnits > 0 &&
                    (tx.vout.size() < 4 || !IsPoolDustToPubKey(tx.vout[3], swap.vchTraderPubKey)))
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-note-change-output");
        } else {
            if (swap.nAmountOut >= swap.nPriorNoteReserve)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-amounts");
            if ((unsigned __int128)(uint64_t)swap.amountPriorBtxReserve + swap.nAmountIn > (unsigned __int128)POOL_MAX_AMOUNT)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-amounts");
            // Trader note inputs are forbidden in dir 2: no note change exists.
            if (swap.nNoteChangeUnits != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-change");
            if (!CheckPoolEscrowPair(tx, swap.nPoolID, swap.amountPriorBtxReserve + (CAmount)swap.nAmountIn, state))
                return false;
            if (!IsPoolDustToPubKey(tx.vout[2], swap.vchTraderPubKey))
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-note-payout");
        }
    }
    else { // POOL_OP_RETIRE
        PoolRetire ret;
        if (!DecodePoolPayload(tx.vchPoolPayload, ret))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-payload");
        if (ret.nPoolID == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-id");
        // Floor-gated: valid only when every issued LP share has been removed and
        // only the never-issued locked floor remains (context-free; the record
        // equality is contextual).
        if (ret.nPriorLpSupply != POOL_MIN_LIQUIDITY)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-not-floor");
        if (ret.nPriorNoteReserve == 0 || ret.nPriorNoteReserve > POOL_MAX_AMOUNT)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-amounts");
        if (ret.amountPriorBtxReserve <= 0 || (uint64_t)ret.amountPriorBtxReserve > POOL_MAX_AMOUNT)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-amounts");
        if (ret.nFeeBps < POOL_FEE_BPS_MIN || ret.nFeeBps > POOL_FEE_BPS_MAX)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-fee");
        // EXACTLY one auth path populated. Single-partner (insolvency liveness):
        // vchTriggerSig set, approver arrays empty. M-of-N (any status): approver
        // arrays set, vchTriggerSig empty and nTriggerPartnerIndex pinned to 0
        // (it is bound into the sighash). The status conditions are contextual.
        const bool fSingle = !ret.vchTriggerSig.empty();
        const bool fMulti = !ret.vApproverIndex.empty();
        if (fSingle == fMulti)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-auth-shape");
        if (fSingle) {
            if (!IsPoolSigShape(ret.vchTriggerSig) ||
                    !ret.vApproverIndex.empty() || !ret.vApproverSig.empty())
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-auth-shape");
        } else {
            if (!ret.vchTriggerSig.empty() || ret.nTriggerPartnerIndex != 0 ||
                    ret.vApproverIndex.size() != ret.vApproverSig.size())
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-auth-shape");
            for (size_t i = 0; i < ret.vApproverIndex.size(); i++) {
                if (i > 0 && ret.vApproverIndex[i] <= ret.vApproverIndex[i - 1])
                    return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-approvers");
                if (!IsPoolSigShape(ret.vApproverSig[i]))
                    return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-approvers");
            }
        }
        // Spends the canonical custody pair (identity pinned contextually).
        if (tx.vin.size() < 2)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-vin-size");
        // Forced floor-BTX payout at vout[0]: P2PKH valued >= Y. The EXACT
        // destination P2PKH(house.vchRedemptionDestPK) is pinned contextually.
        if (tx.vout.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-vout-size");
        if (!IsPoolP2PKHShape(tx.vout[0].scriptPubKey) ||
                tx.vout[0].nValue < ret.amountPriorBtxReserve)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-payout");
        // Terminal: NO output may carry an escrow shape (it would enter the UTXO
        // set untagged - SETTLE's stray-escrow rule; the anyone-can-spend script
        // is only ever safe while the fPoolEscrow tag guards it).
        for (const CTxOut& out : tx.vout) {
            if (IsPoolEscrowScript(out.scriptPubKey))
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-stray-escrow");
        }
    }

    return true;
}

/** floor(sqrt(n)) by Newton's method; monotone-decreasing from x0 = n so it
 * terminates, and the loop invariant keeps the result the floor root. */
static uint64_t Isqrt128(unsigned __int128 n)
{
    if (n == 0)
        return 0;
    unsigned __int128 x = n;
    unsigned __int128 y = (x + 1) / 2;
    while (y < x) {
        x = y;
        y = (x + n / x) / 2;
    }
    return (uint64_t)x;   // inputs bounded by POOL_MAX_AMOUNT^2 < 2^106 -> root < 2^53
}

uint64_t PoolIsqrtProduct(uint64_t a, uint64_t b)
{
    if (a == 0 || b == 0 || a > POOL_MAX_AMOUNT || b > POOL_MAX_AMOUNT)
        return 0;
    return Isqrt128((unsigned __int128)a * (unsigned __int128)b);
}

bool PoolLpMintInitial(uint64_t nInitNote, CAmount amountInitBtx, uint64_t& nLpToCreator, uint64_t& nLpSupply0)
{
    nLpToCreator = 0;
    nLpSupply0 = 0;
    if (amountInitBtx <= 0 || (uint64_t)amountInitBtx > POOL_MAX_AMOUNT)
        return false;
    const uint64_t s0 = PoolIsqrtProduct(nInitNote, (uint64_t)amountInitBtx);
    if (s0 <= POOL_MIN_LIQUIDITY)
        return false;   // seed too small: the creator must receive >= 1 unit past the locked floor
    nLpSupply0 = s0;
    nLpToCreator = s0 - POOL_MIN_LIQUIDITY;
    return true;
}

bool PoolLpMintProportional(uint64_t nAddNote, CAmount amountAddBtx,
                            uint64_t nNoteReserve, CAmount amountBtxReserve, uint64_t nLpSupply,
                            uint64_t& nLpMinted)
{
    nLpMinted = 0;
    if (nAddNote == 0 || amountAddBtx <= 0)
        return false;
    if (nNoteReserve == 0 || amountBtxReserve <= 0 || nLpSupply == 0)
        return false;
    if (nAddNote > POOL_MAX_AMOUNT || (uint64_t)amountAddBtx > POOL_MAX_AMOUNT ||
        nNoteReserve > POOL_MAX_AMOUNT || (uint64_t)amountBtxReserve > POOL_MAX_AMOUNT ||
        nLpSupply > POOL_MAX_AMOUNT)
        return false;

    const unsigned __int128 byNote = (unsigned __int128)nAddNote * (unsigned __int128)nLpSupply
                                   / (unsigned __int128)nNoteReserve;
    const unsigned __int128 byBtx = (unsigned __int128)(uint64_t)amountAddBtx * (unsigned __int128)nLpSupply
                                  / (unsigned __int128)(uint64_t)amountBtxReserve;
    const unsigned __int128 minted = byNote < byBtx ? byNote : byBtx;
    if (minted == 0)
        return false;
    // Post-add magnitudes must stay inside the u128-safe envelope.
    if (minted > (unsigned __int128)POOL_MAX_AMOUNT ||
        (unsigned __int128)nLpSupply + minted > (unsigned __int128)POOL_MAX_AMOUNT ||
        (unsigned __int128)nNoteReserve + nAddNote > (unsigned __int128)POOL_MAX_AMOUNT ||
        (unsigned __int128)(uint64_t)amountBtxReserve + (uint64_t)amountAddBtx > (unsigned __int128)POOL_MAX_AMOUNT)
        return false;

    nLpMinted = (uint64_t)minted;
    return true;
}

bool PoolLpRedeemAmounts(uint64_t nBurnLp,
                         uint64_t nNoteReserve, CAmount amountBtxReserve, uint64_t nLpSupply,
                         uint64_t& nNoteOut, CAmount& amountBtxOut)
{
    nNoteOut = 0;
    amountBtxOut = 0;
    if (nBurnLp == 0 || nLpSupply == 0 || nNoteReserve == 0 || amountBtxReserve <= 0)
        return false;
    if (nBurnLp > POOL_MAX_AMOUNT || nLpSupply > POOL_MAX_AMOUNT ||
        nNoteReserve > POOL_MAX_AMOUNT || (uint64_t)amountBtxReserve > POOL_MAX_AMOUNT)
        return false;
    if (nBurnLp > nLpSupply || nLpSupply - nBurnLp < POOL_MIN_LIQUIDITY)
        return false;   // the locked floor is never redeemable - the pool cannot fully drain

    const unsigned __int128 noteOut = (unsigned __int128)nBurnLp * (unsigned __int128)nNoteReserve
                                    / (unsigned __int128)nLpSupply;
    const unsigned __int128 btxOut = (unsigned __int128)nBurnLp * (unsigned __int128)(uint64_t)amountBtxReserve
                                   / (unsigned __int128)nLpSupply;
    // Zero-side companion (liveness): a payout side that floors to 0 is OMITTED
    // downstream (that output is not created; the forgone dust stays in the
    // reserve for RETIRE to burn/sweep), NOT rejected - so a small LP in a
    // swap-skewed pool can always burn its full position and the pool can always
    // be brought to the floor. A 0-unit note coin is never created (the note
    // payout output is simply absent). Only a burn that pays NOTHING is invalid.
    if (noteOut == 0 && btxOut == 0)
        return false;

    // burn <= S - MIN_LIQUIDITY < S keeps both floors strictly below the reserves.
    nNoteOut = (uint64_t)noteOut;
    amountBtxOut = (CAmount)(uint64_t)btxOut;
    return true;
}

bool PoolSwapOut(uint64_t nAmountIn, uint64_t nReserveIn, uint64_t nReserveOut,
                 uint32_t nFeeBps, uint64_t& nAmountOut)
{
    nAmountOut = 0;
    if (nAmountIn == 0 || nReserveIn == 0 || nReserveOut == 0)
        return false;
    if (nFeeBps < POOL_FEE_BPS_MIN || nFeeBps > POOL_FEE_BPS_MAX)
        return false;
    if (nAmountIn > POOL_MAX_AMOUNT || nReserveIn > POOL_MAX_AMOUNT || nReserveOut > POOL_MAX_AMOUNT)
        return false;
    if ((unsigned __int128)nReserveIn + nAmountIn > (unsigned __int128)POOL_MAX_AMOUNT)
        return false;   // post-swap in-side reserve must stay inside the envelope

    // out = inFee * Rout / (Rin * 10000 + inFee), inFee = in * (10000 - fee).
    // Everything < 2^53 pre-check, so inFee < 2^67 and inFee*Rout < 2^120: u128-safe.
    const unsigned __int128 inFee = (unsigned __int128)nAmountIn * (unsigned __int128)(10000 - nFeeBps);
    const unsigned __int128 num = inFee * (unsigned __int128)nReserveOut;
    const unsigned __int128 den = (unsigned __int128)nReserveIn * 10000 + inFee;
    const unsigned __int128 out = num / den;

    if (out == 0)
        return false;
    if (out >= (unsigned __int128)nReserveOut)
        return false;   // the pool always keeps at least one unit of the out side

    nAmountOut = (uint64_t)out;
    return true;
}
