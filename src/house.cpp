// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <house.h>

#include <consensus/validation.h>
#include <hash.h>
#include <pubkey.h>
#include <script/standard.h>
#include <streams.h>
#include <version.h>

// Consensus defaults; regtest-only init.cpp overrides (integration gates).
uint32_t HOUSE_ATTEST_CADENCE = 144;
uint32_t HOUSE_STRESSED_WINDOW = 1008;
uint32_t HOUSE_DEFER_WINDOW = 12960;   // 90 days (R-1, sim D2)

uint256 HouseDeclarationDigest(const HouseRegister& reg)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankHouse/declaration");
    ss << reg.nTier;
    ss << reg.nThresholdM;
    ss << reg.strClassID;
    ss << reg.nDenomMgGold;
    ss << reg.vchRedemptionDestPK;
    ss << reg.vPartnerPubKey;
    ss << reg.vPledgeAmount;
    return ss.GetHash();
}

uint256 HouseIDFromDeclaration(const HouseRegister& reg)
{
    // Content-derived identity (the register txid cannot appear inside its own
    // outputs). Two registrations with identical declarations collide, but the
    // class-id uniqueness index rejects the second one anyway.
    return HouseDeclarationDigest(reg);
}

uint256 HouseRegisterSigHash(const uint256& declDigest, uint32_t nPartnerIndex, const CAmount& amountPledge)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankHouse/register");
    ss << declDigest;
    ss << nPartnerIndex;
    ss << amountPledge;   // binds the posted bond (Bills-ISSUE pattern)
    return ss.GetHash();
}

uint256 HouseTopupSigHash(const uint256& houseID, uint32_t nPartnerIndex, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankHouse/topup");
    ss << houseID;
    ss << nPartnerIndex;
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 HouseAdmitSigHash(const uint256& houseID, const std::vector<unsigned char>& vchNewPubKey, const CAmount& amountPledge)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankHouse/admit");
    ss << houseID;
    ss << vchNewPubKey;
    ss << amountPledge;
    return ss.GetHash();
}

uint256 HouseExitSigHash(const uint256& houseID, uint32_t nPartnerIndex, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankHouse/exit");
    ss << houseID;
    ss << nPartnerIndex;
    ss << hashOutputs;   // freshness: a leaked exit sig is not a bearer token
    return ss.GetHash();
}

uint256 HouseWinddownSigHash(const uint256& houseID, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankHouse/winddown");
    ss << houseID;
    ss << hashOutputs;   // freshness: a leaked winddown sig is not replayable
    return ss.GetHash();
}

uint256 HouseReclaimSigHash(const uint256& houseID, uint32_t nPartnerIndex, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankHouse/reclaim");
    ss << houseID;
    ss << nPartnerIndex;
    ss << hashOutputs;   // binds the reclaim destination
    return ss.GetHash();
}

uint256 HouseDeferSigHash(const uint256& houseID, uint32_t nPrevLastActivation, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankHouse/defer");
    ss << houseID;
    // Bind the anti-replay ANCHOR, not the invocation height. Binding the
    // height would make an invocation valid in exactly ONE block: any mempool
    // delay would silently invalidate the house's crisis tool at the moment it
    // needs it. The prior-activation value is what a replay cannot reproduce
    // (connect requires it to equal the DB, and a DEFER moves it).
    ss << nPrevLastActivation;
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 HouseRenewSigHash(const uint256& houseID, uint32_t nRenewalIndex, const uint256& hashPrevouts, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankHouse/renew");
    ss << houseID;
    ss << nRenewalIndex;   // binds WHICH renewal within an episode
    // nRenewalIndex resets to 0 at every DEFER, so it alone does NOT distinguish
    // one episode's renewal from a later episode's - and the escrow coins are
    // OP_TRUE, so the approver signature is the sole authorization. Bind the tx
    // prevouts (as MINT does) so an approval cannot be replayed into a different
    // episode: a replay must spend different (already-consumed) inputs.
    ss << hashPrevouts;
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 HouseReleaseSigHash(const uint256& houseID, const uint256& hashPrevouts, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankHouse/release");
    ss << houseID;
    // The reserve-till coins are OP_TRUE anyone-can-spend, so this approver
    // signature is the ONLY gate on moving them. Binding only houseID+outputs
    // leaves it replayable in a later deferral episode against a fresh till.
    // Bind the tx prevouts (the exact till coins being released) so the approval
    // is unique to this episode's coins.
    ss << hashPrevouts;
    ss << hashOutputs;   // binds where the released till goes
    return ss.GetHash();
}

uint256 HouseAttestChallenge(const uint256& houseID, uint32_t nAsOfHeight,
                             const uint256& hashAsOfBlock, const COutPoint& outpoint)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankReserveProof");
    ss << houseID;         // cross-house proof replay bar
    ss << nAsOfHeight;
    ss << hashAsOfBlock;   // recency: reorg past nAsOfHeight kills every proof
    ss << outpoint;
    return ss.GetHash();
}

uint256 HouseAttestProofSetHash(const std::vector<AttestProof>& vProofs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankHouse/proofset");
    for (const AttestProof& p : vProofs) {
        ss << p.outpoint;
        ss << p.vchPubKey;   // deliberately NOT vchSig - sigs gathered after the set is fixed
    }
    return ss.GetHash();
}

uint256 HouseAttestSigHash(const uint256& houseID, uint32_t nAsOfHeight,
                           const CAmount& amountReserves, const uint256& hashProofSet,
                           const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankHouse/attest");
    ss << houseID;
    ss << nAsOfHeight;
    ss << amountReserves;
    ss << hashProofSet;
    ss << hashOutputs;
    return ss.GetHash();
}

CScript HouseEscrowScript(const uint256& houseID)
{
    return CScript() << std::vector<unsigned char>(houseID.begin(), houseID.end()) << OP_DROP << OP_TRUE;
}

bool IsHouseEscrowScript(const CScript& script)
{
    // <32-byte push> OP_DROP OP_TRUE - same family as the bill escrow; the
    // two are distinguished by the coin tags (fHouseEscrow vs fBillEscrow),
    // never by script inspection.
    return script.size() == 35 && script[0] == 0x20 &&
           script[33] == OP_DROP && script[34] == OP_TRUE;
}

bool IsValidHouseClassID(const std::string& strClassID)
{
    if (strClassID.empty() || strClassID.size() > MAX_HOUSE_CLASS_ID_BYTES)
        return false;

    for (const char c : strClassID) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')))
            return false;
    }
    return true;
}

uint32_t HouseStressOrigin(const CHouse& house, int nHeight)
{
    // The stress origin is the EARLIER of the ratio breach recorded by ATTEST
    // and the (derived) missed-cadence deadline; an in-band attestation
    // preserves nStressSinceHeight, so the window clock never resets without
    // a real recovery (T4).
    uint32_t nStress = house.nStressSinceHeight;
    const uint32_t nDeadline = house.nLastAttestHeight
                             + HOUSE_ATTEST_MISS_N * HOUSE_ATTEST_CADENCE;
    if (nHeight >= 0 && (uint32_t)nHeight > nDeadline &&
        (nStress == 0 || nDeadline + 1 < nStress))
        nStress = nDeadline + 1;
    return nStress;
}

char HouseEffectiveStatus(const CHouse& house, int nHeight)
{
    if (house.status == HOUSE_STATUS_WOUNDDOWN) return HOUSE_STATUS_WOUNDDOWN;
    if (house.status == HOUSE_STATUS_INSOLVENT) return HOUSE_STATUS_INSOLVENT; // materialized

    // Option clause (3.5): an invoked deferral REPLACES the ordinary stress
    // clock with the deferral window - the whole point is to stop the par
    // drain and buy time for reflux and recovery capital. Still fully lazy:
    // 'd' and the post-expiry 'i' are derived from the stored invocation
    // height, so invoking writes once and nothing sweeps thereafter.
    if (house.nDeferInvokedHeight != 0) {
        const uint32_t nEnd = house.DeferEndHeight();
        if (nHeight >= 0 && (uint32_t)nHeight >= nEnd)
            return HOUSE_STATUS_INSOLVENT;   // window ran out without recovery (ARCH s7 step 6)
        return HOUSE_STATUS_DEFERRED;
    }

    // Stored status is 'o' and no deferral - the 3.4 derivation
    const uint32_t nStress = HouseStressOrigin(house, nHeight);
    if (nStress == 0) return HOUSE_STATUS_OPEN;
    if ((uint32_t)nHeight >= nStress + HOUSE_STRESSED_WINDOW)
        return HOUSE_STATUS_INSOLVENT;                          // window expiry
    return HOUSE_STATUS_STRESSED;
}

bool HouseConfidenceDead(const CHouse& house, int nHeight)
{
    // Cumulative suspension beyond the cap (counting any episode running now)
    if (house.DeferSuspendedBlocks(nHeight) >= HOUSE_CD_MAX_SUSPENDED)
        return true;
    // A second activation inside the CD window
    if (house.nDeferActivations > 0 && nHeight >= 0 &&
            (uint32_t)nHeight < house.nDeferLastActivation + HOUSE_CD_WINDOW_BLOCKS)
        return true;
    return false;
}

uint64_t HouseCapitalCapUnits(const CHouse& house)
{
    const uint32_t nTierIdx = house.nTier <= MAX_HOUSE_TIER ? house.nTier : 0;
    // lambdaX10 * E <= 30 * 2.1e15, inside u64
    return ((uint64_t)HOUSE_LAMBDA_X10[nTierIdx] * (uint64_t)house.ActiveEscrow()) / 10;
}

uint64_t HouseReserveCapUnits(const CHouse& house)
{
    // R * 100 <= MAX_MONEY * 100 = 2.1e17, inside u64
    return ((uint64_t)house.amountLastAttestReserves * 100) / HOUSE_RESERVE_FLOOR_PCT;
}

uint64_t HouseMintCapUnits(const CHouse& house)
{
    const uint64_t nCapital = HouseCapitalCapUnits(house);
    const uint64_t nReserve = HouseReserveCapUnits(house);
    return nCapital < nReserve ? nCapital : nReserve;
}

uint32_t HouseAttestedRatioBps(const CHouse& house)
{
    if (house.nMintedUnits == 0)
        return 10000;   // no liabilities -> fully covered by definition
    // R * 10000 <= MAX_MONEY * 10000 = 2.1e19 - that WOULD overflow u64
    // (1.8e19), so take the 128-bit path.
    const unsigned __int128 num = (unsigned __int128)(uint64_t)house.amountLastAttestReserves * 10000;
    const unsigned __int128 bps = num / (unsigned __int128)house.nMintedUnits;
    return bps > 10000 ? 10000 : (uint32_t)bps;
}

uint32_t HouseBrassageBps(const CHouse& house)
{
    const uint32_t nRho = HOUSE_RESERVE_FLOOR_PCT * 100;   // rho in bps
    const uint32_t nRatio = HouseAttestedRatioBps(house);

    // At or above the floor: exact PAR. An Open house is always here (a
    // below-floor attestation is what makes a house Stressed), so the spread
    // only ever bites on a publicly impaired house.
    if (nRatio >= nRho)
        return 0;
    // At or below theta: the full spread.
    if (nRatio <= HOUSE_THETA_BPS)
        return HOUSE_BRASSAGE_MAX_BPS;

    // Between: quadratic in proximity (the sim's prox^2 - zero first derivative
    // at rho, so the fee opens gently instead of with a cliff at the floor).
    const uint64_t nNum = nRho - nRatio;                   // 0 .. (rho - theta)
    const uint64_t nDen = nRho - HOUSE_THETA_BPS;          // rho - theta (750)
    return (uint32_t)(((uint64_t)HOUSE_BRASSAGE_MAX_BPS * nNum * nNum) / (nDen * nDen));
}

CAmount HouseBrassageAmount(uint64_t nUnits, uint32_t nBps)
{
    if (nUnits == 0 || nBps == 0)
        return 0;
    const unsigned __int128 amt = (unsigned __int128)nUnits * (unsigned __int128)nBps / 10000;
    return amt > (unsigned __int128)MAX_MONEY ? (CAmount)MAX_MONEY : (CAmount)amt;
}

uint32_t HouseDepositWAM(const CHouse& house, int nHeight)
{
    if (house.nDepositUnits == 0)
        return 0;
    // Weighted-average maturity HEIGHT = Sigma(principal*maturity) / Sigma(principal).
    const unsigned __int128 wtHeight = house.DepositWtMaturity() / (unsigned __int128)house.nDepositUnits;
    const unsigned __int128 h = nHeight > 0 ? (unsigned __int128)nHeight : 0;
    if (wtHeight <= h)
        return 0;   // all deposits already matured on average
    const unsigned __int128 remaining = wtHeight - h;
    return remaining > (unsigned __int128)0xffffffffULL ? 0xffffffffU : (uint32_t)remaining;
}

uint32_t HouseLoanBookSliceWAM(const CHouse& /*house*/, int /*nHeight*/)
{
    // v1 STUB: no discounting op exists, so the performing loan book L is
    // structurally 0 and the deposit-funded slice max(0, L - escrow) is 0.
    return 0;
}

bool HouseMatchFundingOK(const CHouse& house, int nHeight)
{
    return HouseDepositWAM(house, nHeight) >= HouseLoanBookSliceWAM(house, nHeight);
}

uint32_t HouseAttestNewStressOrigin(const CHouse& house, const CAmount& amountReserves, int nHeight)
{
    // All quantities are far inside uint64: R*100 <= MAX_MONEY*100 and
    // pct*N <= 15 * 3*MAX_MONEY (the mint cap bounds nMintedUnits by
    // lambda*escrow <= 3*MAX_MONEY).
    const uint64_t nR100 = (uint64_t)amountReserves * 100;
    const uint64_t nFloorTarget = (uint64_t)HOUSE_RESERVE_FLOOR_PCT * house.nMintedUnits;
    const uint64_t nBufferTarget = (uint64_t)(HOUSE_RESERVE_FLOOR_PCT + HOUSE_RESTORE_BUFFER_PCT) * house.nMintedUnits;

    // Effective origin BEFORE this attestation moves the cadence clock: a
    // below-floor or in-band attestation must MATERIALIZE a lazy missed-
    // cadence origin (writing nLastAttestHeight would otherwise erase it).
    const uint32_t nEffStress = HouseStressOrigin(house, nHeight);
    if (nR100 < nFloorTarget)
        return nEffStress ? nEffStress : (uint32_t)nHeight;    // T2: below floor
    if (nR100 >= nBufferTarget)
        return 0;                                              // T4: recovery (hysteresis, D9)
    return nEffStress;                                         // in-band: preserve state
}

template <typename T>
bool DecodeHousePayload(const std::vector<unsigned char>& vch, T& payload)
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

template bool DecodeHousePayload<HouseRegister>(const std::vector<unsigned char>&, HouseRegister&);
template bool DecodeHousePayload<HouseTopup>(const std::vector<unsigned char>&, HouseTopup&);
template bool DecodeHousePayload<HouseAdmit>(const std::vector<unsigned char>&, HouseAdmit&);
template bool DecodeHousePayload<HouseExit>(const std::vector<unsigned char>&, HouseExit&);
template bool DecodeHousePayload<HouseWinddown>(const std::vector<unsigned char>&, HouseWinddown&);
template bool DecodeHousePayload<HouseReclaim>(const std::vector<unsigned char>&, HouseReclaim&);
template bool DecodeHousePayload<HouseAttest>(const std::vector<unsigned char>&, HouseAttest&);
template bool DecodeHousePayload<HouseDefer>(const std::vector<unsigned char>&, HouseDefer&);
template bool DecodeHousePayload<HouseRenew>(const std::vector<unsigned char>&, HouseRenew&);
template bool DecodeHousePayload<HouseRelease>(const std::vector<unsigned char>&, HouseRelease&);

static bool IsValidHousePubKey(const std::vector<unsigned char>& vch)
{
    if (vch.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE)
        return false;

    CPubKey pubkey(vch);
    return pubkey.IsFullyValid();
}

/** Approver lists must be strictly ascending (no duplicates), sized exactly M,
 * with one signature per index. Index bounds against the CURRENT partner set
 * are contextual (CheckHouseOperation); this checks internal coherence only. */
static bool CheckApproverShape(const std::vector<uint32_t>& vIndex,
                               const std::vector<std::vector<unsigned char>>& vSig)
{
    if (vIndex.size() != vSig.size())
        return false;
    if (vIndex.size() > MAX_HOUSE_PARTNERS)
        return false;

    for (size_t i = 0; i < vIndex.size(); i++) {
        if (i > 0 && vIndex[i] <= vIndex[i - 1])
            return false;
        if (vSig[i].empty() || vSig[i].size() > 80)
            return false;
    }
    return true;
}

bool CheckHouseTransactionShape(const CTransaction& tx, CValidationState& state)
{
    if (tx.IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-house-coinbase");

    if (tx.nHouseOp < HOUSE_OP_REGISTER || tx.nHouseOp > HOUSE_OP_RELEASE)
        return state.DoS(100, false, REJECT_INVALID, "bad-house-op");

    // Register: 64 partners x (33B key + 72B sig + amount) + declaration
    if (tx.vchHousePayload.size() > 16384)
        return state.DoS(100, false, REJECT_INVALID, "bad-house-payload-oversize");

    if (tx.nHouseOp == HOUSE_OP_REGISTER) {
        HouseRegister reg;
        if (!DecodeHousePayload(tx.vchHousePayload, reg))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-register-payload");

        if (reg.nTier > MAX_HOUSE_TIER)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-register-tier");
        if (!IsValidHouseClassID(reg.strClassID))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-register-classid");
        if (reg.nDenomMgGold == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-register-denom");
        if (!IsValidHousePubKey(reg.vchRedemptionDestPK))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-register-redemptionpk");

        const size_t nPartners = reg.vPartnerPubKey.size();
        if (nPartners == 0 || nPartners > MAX_HOUSE_PARTNERS)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-register-partner-count");
        if (reg.vPledgeAmount.size() != nPartners || reg.vPartnerSig.size() != nPartners)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-register-parallel-arrays");

        // Tier / set-size / threshold coherence
        const bool fSolo = (reg.nTier == HOUSE_TIER_BONDED_SOLO || reg.nTier == HOUSE_TIER_ENCUMBERED_SOLO);
        if (fSolo && (nPartners != 1 || reg.nThresholdM != 1))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-register-solo-shape");
        if (!fSolo && nPartners < 2)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-register-multi-size");
        if (reg.nThresholdM < 1 || reg.nThresholdM > nPartners)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-register-threshold");
        // Multi-partner tiers need a real quorum: M==1 is single-point control
        // (one partner could unilaterally admit/expel/wind down), which defeats
        // the co-liability the tier exists for.
        if (!fSolo && reg.nThresholdM < 2)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-register-multi-threshold");

        // Per-partner: valid distinct keys, pledge floor, pledge output at vout[i]
        if (tx.vout.size() < nPartners)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-register-vout-size");

        const uint256 houseID = HouseIDFromDeclaration(reg);
        const CScript escrowScript = HouseEscrowScript(houseID);
        for (size_t i = 0; i < nPartners; i++) {
            if (!IsValidHousePubKey(reg.vPartnerPubKey[i]))
                return state.DoS(100, false, REJECT_INVALID, "bad-house-register-pubkey");
            for (size_t j = 0; j < i; j++) {
                if (reg.vPartnerPubKey[j] == reg.vPartnerPubKey[i])
                    return state.DoS(100, false, REJECT_INVALID, "bad-house-register-dup-key");
            }
            if (reg.vPledgeAmount[i] < HOUSE_MIN_PLEDGE || reg.vPledgeAmount[i] > MAX_MONEY)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-register-pledge");
            if (tx.vout[i].nValue != reg.vPledgeAmount[i] ||
                    tx.vout[i].scriptPubKey != escrowScript)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-register-escrow");
        }
        // Partner ECDSA verifies run contextually (CheckHouseOperation, after
        // CheckTxInputs) - same DoS pricing rationale as Bills ISSUE.
    }
    else
    if (tx.nHouseOp == HOUSE_OP_TOPUP) {
        HouseTopup topup;
        if (!DecodeHousePayload(tx.vchHousePayload, topup))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-topup-payload");

        // vout[0] must exist to carry the added pledge; the script is checked
        // contextually (needs the house record for houseID).
        if (tx.vout.empty() || tx.vout[0].nValue <= 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-topup-vout");
    }
    else
    if (tx.nHouseOp == HOUSE_OP_ADMIT) {
        HouseAdmit admit;
        if (!DecodeHousePayload(tx.vchHousePayload, admit))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-admit-payload");

        if (!IsValidHousePubKey(admit.vchNewPubKey))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-admit-pubkey");
        if (!CheckApproverShape(admit.vApproverIndex, admit.vApproverSig) || admit.vApproverIndex.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-house-admit-approvers");
        if (tx.vout.empty() || tx.vout[0].nValue < HOUSE_MIN_PLEDGE)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-admit-vout");
    }
    else
    if (tx.nHouseOp == HOUSE_OP_EXIT) {
        HouseExit ex;
        if (!DecodeHousePayload(tx.vchHousePayload, ex))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-exit-payload");

        // Either the partner's own signature (voluntary) or an approver set
        // (expulsion) must be present; both is fine too.
        if (ex.vchPartnerSig.empty() && ex.vApproverIndex.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-house-exit-noauth");
        if (!CheckApproverShape(ex.vApproverIndex, ex.vApproverSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-exit-approvers");
    }
    else
    if (tx.nHouseOp == HOUSE_OP_WINDDOWN) {
        HouseWinddown wd;
        if (!DecodeHousePayload(tx.vchHousePayload, wd))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-winddown-payload");

        if (!CheckApproverShape(wd.vApproverIndex, wd.vApproverSig) || wd.vApproverIndex.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-house-winddown-approvers");
    }
    else
    if (tx.nHouseOp == HOUSE_OP_RECLAIM) {
        HouseReclaim rec;
        if (!DecodeHousePayload(tx.vchHousePayload, rec))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-reclaim-payload");

        if (rec.vchSig.empty() || rec.vchSig.size() > 80)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-reclaim-sig");
    }
    else
    if (tx.nHouseOp == HOUSE_OP_ATTEST) {
        HouseAttest att;
        if (!DecodeHousePayload(tx.vchHousePayload, att))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-payload");

        if (att.nSchemaVersion != 1)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-schema");
        if (att.amountReserves < 0 || att.amountReserves > MAX_MONEY ||
                att.amountPrevReserves < 0 || att.amountPrevReserves > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-amount");
        if (att.vProofs.size() > MAX_ATTEST_PROOFS)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-proof-count");
        // A zero-reserve attestation carries no proofs; a positive claim needs
        // at least one (their value sum is checked contextually).
        if (att.vProofs.empty() != (att.amountReserves == 0))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-proof-count");

        // Outpoints must be non-null and UNIQUE - a duplicate proof would
        // double-count its coin toward the reserve sum.
        for (size_t i = 0; i < att.vProofs.size(); i++) {
            const AttestProof& p = att.vProofs[i];
            if (p.outpoint.IsNull())
                return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-outpoint");
            if (!IsValidHousePubKey(p.vchPubKey))
                return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-proof-pubkey");
            if (p.vchSig.empty() || p.vchSig.size() > 80)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-proof-sig");
            for (size_t j = 0; j < i; j++) {
                if (att.vProofs[j].outpoint == p.outpoint)
                    return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-dup-outpoint");
            }
        }

        if (!CheckApproverShape(att.vApproverIndex, att.vApproverSig) || att.vApproverIndex.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-approvers");
        // Proof + approver ECDSA runs contextually (CheckHouseOperation, after
        // CheckTxInputs) - Bills DoS pricing.
    }
    else
    if (tx.nHouseOp == HOUSE_OP_DEFER) {
        HouseDefer def;
        if (!DecodeHousePayload(tx.vchHousePayload, def))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-defer-payload");

        if (!CheckApproverShape(def.vApproverIndex, def.vApproverSig) || def.vApproverIndex.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-house-defer-approvers");
        // vout[0] carries the till lock; its script/value are contextual (they
        // need the house record and its attested reserves).
        if (tx.vout.empty() || tx.vout[0].nValue <= 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-defer-vout");
    }
    else
    if (tx.nHouseOp == HOUSE_OP_RENEW) {
        HouseRenew ren;
        if (!DecodeHousePayload(tx.vchHousePayload, ren))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-renew-payload");

        if (!CheckApproverShape(ren.vApproverIndex, ren.vApproverSig) || ren.vApproverIndex.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-house-renew-approvers");
    }
    else
    if (tx.nHouseOp == HOUSE_OP_RELEASE) {
        HouseRelease rel;
        if (!DecodeHousePayload(tx.vchHousePayload, rel))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-release-payload");

        if (!CheckApproverShape(rel.vApproverIndex, rel.vApproverSig) || rel.vApproverIndex.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-house-release-approvers");
    }

    return true;
}
