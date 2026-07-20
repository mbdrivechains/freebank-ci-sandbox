// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <note.h>

#include <house.h>   // HOUSE_DEFER_INTEREST_BPS / BLOCKS_PER_YEAR (deferral interest)

#include <consensus/validation.h>
#include <hash.h>
#include <set>
#include <pubkey.h>
#include <script/standard.h>
#include <streams.h>
#include <version.h>

CScript NoteScriptForPubKey(const std::vector<unsigned char>& vchPubKey)
{
    CPubKey pubkey(vchPubKey);
    return GetScriptForDestination(pubkey.GetID());
}

static bool IsNoteP2PKH(const CScript& script)
{
    // OP_DUP OP_HASH160 <20-byte push> OP_EQUALVERIFY OP_CHECKSIG
    return script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 &&
           script[2] == 0x14 && script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG;
}

uint256 NoteHashPrevouts(const CTransaction& tx)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (const CTxIn& in : tx.vin)
        ss << in.prevout;
    return ss.GetHash();
}

uint256 NoteMintSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits, const uint256& hashPrevouts, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankNote/mint");
    ss << nHouseID;
    ss << vUnits;
    ss << hashPrevouts;   // tx-unique -> a mint's approver sigs are not replayable
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 NoteTransferSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankNote/transfer");
    ss << nHouseID;
    ss << vUnits;
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 NoteRedeemSigHash(uint32_t nHouseID, uint64_t nUnitsBurned, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankNote/redeem");
    ss << nHouseID;
    ss << nUnitsBurned;
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 NoteClaimSigHash(uint32_t nHouseID, uint64_t nUnitsBurned, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankNote/claim");
    ss << nHouseID;
    ss << nUnitsBurned;
    ss << hashOutputs;   // binds payout + escrow change exactly
    return ss.GetHash();
}

uint256 NoteDemandSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankNote/demand");
    ss << nHouseID;
    ss << vUnits;
    ss << hashOutputs;
    return ss.GetHash();
}

CAmount NoteDeferralInterest(uint64_t nUnits, uint32_t nBlocks)
{
    if (nUnits == 0 || nBlocks == 0)
        return 0;
    // units * bps * blocks / (10000 * blocks_per_year); 128-bit intermediate
    const unsigned __int128 num = (unsigned __int128)nUnits
                                * (unsigned __int128)HOUSE_DEFER_INTEREST_BPS
                                * (unsigned __int128)nBlocks;
    const unsigned __int128 den = (unsigned __int128)10000 * (unsigned __int128)BLOCKS_PER_YEAR;
    unsigned __int128 interest = num / den;
    // Never let interest alone leave the money range (a pathological block
    // count would otherwise wrap the payout arithmetic).
    if (interest > (unsigned __int128)MAX_MONEY)
        interest = (unsigned __int128)MAX_MONEY;
    return (CAmount)interest;
}

CAmount NoteClaimEntitlement(uint64_t nUnits, const CAmount& amountPot, uint64_t nSnapshotUnits)
{
    if (nSnapshotUnits == 0 || amountPot <= 0 || nUnits == 0)
        return 0;
    // nUnits <= 3*MAX_MONEY and amountPot <= MAX_MONEY: the product needs
    // ~104 bits - 128-bit intermediate, then the min() caps at par.
    const unsigned __int128 prorata =
        (unsigned __int128)nUnits * (unsigned __int128)amountPot / (unsigned __int128)nSnapshotUnits;
    const unsigned __int128 par = (unsigned __int128)nUnits;
    const unsigned __int128 take = prorata < par ? prorata : par;
    return (CAmount)take;
}

CAmount HouseResidualShare(const CAmount& amountPledge, const CAmount& amountResidual, const CAmount& amountPledgeSum)
{
    if (amountPledgeSum <= 0 || amountResidual <= 0 || amountPledge <= 0)
        return 0;
    return (CAmount)((unsigned __int128)amountPledge * (unsigned __int128)amountResidual
                     / (unsigned __int128)amountPledgeSum);
}

bool SumNoteUnits(const std::vector<uint64_t>& vUnits, uint64_t& total)
{
    total = 0;
    if (vUnits.empty())
        return false;
    for (const uint64_t u : vUnits) {
        if (u == 0)
            return false;
        // Overflow-safe; also keep the total inside the money range so it can
        // never wrap when combined with nMintedUnits / the escrow cap.
        if (u > (uint64_t)MAX_MONEY || total > (uint64_t)MAX_MONEY - u)
            return false;
        total += u;
    }
    return true;
}

template <typename T>
bool DecodeNotePayload(const std::vector<unsigned char>& vch, T& payload)
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

template bool DecodeNotePayload<NoteMint>(const std::vector<unsigned char>&, NoteMint&);
template bool DecodeNotePayload<NoteTransfer>(const std::vector<unsigned char>&, NoteTransfer&);
template bool DecodeNotePayload<NoteRedeem>(const std::vector<unsigned char>&, NoteRedeem&);
template bool DecodeNotePayload<NoteClaim>(const std::vector<unsigned char>&, NoteClaim&);
template bool DecodeNotePayload<NoteDemand>(const std::vector<unsigned char>&, NoteDemand&);

static bool IsValidNotePubKey(const std::vector<unsigned char>& vch)
{
    if (vch.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE)
        return false;
    CPubKey pubkey(vch);
    return pubkey.IsFullyValid();
}

/** vout[0..nUnits-1] must each be a dust-valued P2PKH note output. */
static bool CheckNoteOutputs(const CTransaction& tx, size_t nUnits, CValidationState& state)
{
    if (nUnits == 0 || nUnits > MAX_NOTE_OUTPUTS)
        return state.DoS(100, false, REJECT_INVALID, "bad-note-units-count");
    if (tx.vout.size() < nUnits)
        return state.DoS(100, false, REJECT_INVALID, "bad-note-vout-size");
    for (size_t i = 0; i < nUnits; i++) {
        if (tx.vout[i].nValue != NOTE_DUST_VALUE)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-output-value");
        if (!IsNoteP2PKH(tx.vout[i].scriptPubKey))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-output-script");
    }
    return true;
}

bool CheckNoteTransactionShape(const CTransaction& tx, CValidationState& state)
{
    if (tx.IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-note-coinbase");

    // Reserved v1.5 bearer op-codes are inert in v1 (unreachable).
    if (tx.nNoteOp == NOTE_OP_LOCK || tx.nNoteOp == NOTE_OP_UNLOCK)
        return state.DoS(100, false, REJECT_INVALID, "bad-note-op-reserved");
    if (tx.nNoteOp < NOTE_OP_MINT || tx.nNoteOp > NOTE_OP_DEMAND)
        return state.DoS(100, false, REJECT_INVALID, "bad-note-op");

    // 100 outputs x u64 + M approver sigs + (MINT, R-i7) up to 64 reserve proofs
    // (~145 B each); bounded well above the worst case.
    if (tx.vchNotePayload.size() > 32768)
        return state.DoS(100, false, REJECT_INVALID, "bad-note-payload-oversize");

    if (tx.nNoteOp == NOTE_OP_MINT) {
        NoteMint mint;
        if (!DecodeNotePayload(tx.vchNotePayload, mint))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-payload");

        uint64_t total = 0;
        if (!SumNoteUnits(mint.vUnits, total))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-units");
        if (!CheckNoteOutputs(tx, mint.vUnits.size(), state))
            return false;

        // Approver arrays: non-empty, ascending, sized, sanely bounded. Index
        // ranges vs the current partner set are contextual; ECDSA is contextual.
        if (mint.vApproverIndex.empty() || mint.vApproverIndex.size() != mint.vApproverSig.size())
            return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-approvers");
        for (size_t i = 0; i < mint.vApproverIndex.size(); i++) {
            if (i > 0 && mint.vApproverIndex[i] <= mint.vApproverIndex[i - 1])
                return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-approvers");
            if (mint.vApproverSig[i].empty() || mint.vApproverSig[i].size() > 80)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-approvers");
        }

        // R-i7 reserve proof (context-free shape only; ECDSA + liveness are
        // contextual). Bound the set and each proof's key/sig, and require
        // unique outpoints - mirrors the HOUSE_OP_ATTEST proof shape checks.
        if (mint.vReserveProofs.size() > MAX_ATTEST_PROOFS)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-reserve-count");
        std::set<COutPoint> setProof;
        for (const AttestProof& p : mint.vReserveProofs) {
            if (p.vchPubKey.size() != 33)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-reserve-pubkey");
            if (p.vchSig.empty() || p.vchSig.size() > 80)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-reserve-sig");
            if (!setProof.insert(p.outpoint).second)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-reserve-dup");
        }
    }
    else if (tx.nNoteOp == NOTE_OP_TRANSFER) {
        NoteTransfer xfer;
        if (!DecodeNotePayload(tx.vchNotePayload, xfer))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-transfer-payload");

        uint64_t total = 0;
        if (!SumNoteUnits(xfer.vUnits, total))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-transfer-units");
        if (!CheckNoteOutputs(tx, xfer.vUnits.size(), state))
            return false;
        if (!IsValidNotePubKey(xfer.vchSenderPubKey) ||
                xfer.vchSenderSig.empty() || xfer.vchSenderSig.size() > 80)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-transfer-auth");
    }
    else if (tx.nNoteOp == NOTE_OP_REDEEM) {
        NoteRedeem redeem;
        if (!DecodeNotePayload(tx.vchNotePayload, redeem))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-payload");

        if (!IsValidNotePubKey(redeem.vchHolderPubKey) ||
                redeem.vchHolderSig.empty() || redeem.vchHolderSig.size() > 80)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-auth");
        if (redeem.fBrassage > 1)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-flag");
        // vout[0] = holder payout; vout[1] = the brassage escrow output when
        // flagged. The spread AMOUNT, the escrow script and the >= U payout are
        // contextual (they need the house record and the spent inputs' units).
        if (tx.vout.empty() || (redeem.fBrassage && tx.vout.size() < 2))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-vout");
    }
    else if (tx.nNoteOp == NOTE_OP_DEMAND) {
        NoteDemand dem;
        if (!DecodeNotePayload(tx.vchNotePayload, dem))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-payload");

        uint64_t total = 0;
        if (!SumNoteUnits(dem.vUnits, total))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-units");
        // The notes are RE-ISSUED, not surrendered: same dust P2PKH shape as a
        // transfer, to the same holder.
        if (!CheckNoteOutputs(tx, dem.vUnits.size(), state))
            return false;
        if (!IsValidNotePubKey(dem.vchHolderPubKey) ||
                dem.vchHolderSig.empty() || dem.vchHolderSig.size() > 80)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-auth");
    }
    else if (tx.nNoteOp == NOTE_OP_CLAIM) {
        NoteClaim claim;
        if (!DecodeNotePayload(tx.vchNotePayload, claim))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-payload");

        if (!IsValidNotePubKey(claim.vchHolderPubKey) ||
                claim.vchHolderSig.empty() || claim.vchHolderSig.size() > 80)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-auth");
        if (claim.fEscrowChange > 1)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-flag");
        // vout[0] = payout; escrow change (if flagged) lives at vout[1] with
        // the canonical escrow script (script + entitlement are contextual -
        // they need the house record and the insolvency snapshot).
        if (tx.vout.empty() || (claim.fEscrowChange && tx.vout.size() < 2))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-vout");
    }

    return true;
}
