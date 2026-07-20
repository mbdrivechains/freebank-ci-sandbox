// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <deposit.h>

#include <house.h>   // BLOCKS_PER_YEAR (accrued interest denominator)

#include <consensus/validation.h>
#include <hash.h>
#include <pubkey.h>
#include <script/standard.h>
#include <streams.h>
#include <version.h>

CScript DepositScriptForPubKey(const std::vector<unsigned char>& vchPubKey)
{
    CPubKey pubkey(vchPubKey);
    return GetScriptForDestination(pubkey.GetID());
}

static bool IsDepositP2PKH(const CScript& script)
{
    // OP_DUP OP_HASH160 <20-byte push> OP_EQUALVERIFY OP_CHECKSIG
    return script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 &&
           script[2] == 0x14 && script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG;
}

uint256 DepositHashPrevouts(const CTransaction& tx)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (const CTxIn& in : tx.vin)
        ss << in.prevout;
    return ss.GetHash();
}

uint256 DepositOriginateSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vPrincipal,
                                const std::vector<uint32_t>& vRateBps, const std::vector<uint32_t>& vMaturityHeight,
                                const uint256& hashPrevouts, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankDeposit/originate");
    ss << nHouseID;
    ss << vPrincipal;
    ss << vRateBps;
    ss << vMaturityHeight;
    ss << hashPrevouts;   // tx-unique -> the approver sigs are not replayable
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 DepositTransferSigHash(uint32_t nHouseID, uint64_t nPrincipal, uint32_t nRateBps,
                               uint32_t nMaturityHeight, uint32_t nOriginationHeight, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankDeposit/transfer");
    ss << nHouseID;
    ss << nPrincipal;
    ss << nRateBps;
    ss << nMaturityHeight;
    ss << nOriginationHeight;   // the immutable terms being reassigned
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 DepositWithdrawSigHash(uint32_t nHouseID, uint64_t nPrincipal, uint32_t nMaturityHeight,
                               uint32_t nOriginationHeight, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankDeposit/withdraw");
    ss << nHouseID;
    ss << nPrincipal;
    ss << nMaturityHeight;
    ss << nOriginationHeight;
    ss << hashOutputs;   // binds the exact payout (principal + accrued)
    return ss.GetHash();
}

uint256 DepositClaimSigHash(uint32_t nHouseID, uint64_t nPrincipal, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankDeposit/claim");
    ss << nHouseID;
    ss << nPrincipal;
    ss << hashOutputs;   // binds payout + escrow change exactly
    return ss.GetHash();
}

CAmount DepositMaturityInterest(uint64_t nPrincipal, uint32_t nBlocks, uint32_t nRateBps)
{
    if (nPrincipal == 0 || nBlocks == 0 || nRateBps == 0)
        return 0;
    // principal * rate_bps * blocks / (10000 * blocks_per_year); 128-bit
    // intermediate (principal <= MAX_MONEY times an unbounded block count wraps
    // u64). Simple, not compounding - the receipt's OWN rate, not a fixed one.
    const unsigned __int128 num = (unsigned __int128)nPrincipal
                                * (unsigned __int128)nRateBps
                                * (unsigned __int128)nBlocks;
    const unsigned __int128 den = (unsigned __int128)10000 * (unsigned __int128)BLOCKS_PER_YEAR;
    unsigned __int128 interest = num / den;
    if (interest > (unsigned __int128)MAX_MONEY)
        interest = (unsigned __int128)MAX_MONEY;
    return (CAmount)interest;
}

CAmount DepositClaimEntitlement(uint64_t nPrincipal, const CAmount& amountDepositPot, uint64_t nSnapshotPrincipal)
{
    if (nSnapshotPrincipal == 0 || amountDepositPot <= 0 || nPrincipal == 0)
        return 0;
    // nPrincipal <= MAX_MONEY and amountDepositPot <= MAX_MONEY: 128-bit product,
    // then the min() caps the junior take at par (accrued interest does not
    // survive materialization, symmetric with the note waterfall).
    const unsigned __int128 prorata =
        (unsigned __int128)nPrincipal * (unsigned __int128)amountDepositPot / (unsigned __int128)nSnapshotPrincipal;
    const unsigned __int128 par = (unsigned __int128)nPrincipal;
    const unsigned __int128 take = prorata < par ? prorata : par;
    return (CAmount)take;
}

bool SumDepositPrincipal(const std::vector<uint64_t>& vPrincipal, uint64_t& total)
{
    total = 0;
    if (vPrincipal.empty())
        return false;
    for (const uint64_t p : vPrincipal) {
        if (p == 0)
            return false;
        if (p > (uint64_t)MAX_MONEY || total > (uint64_t)MAX_MONEY - p)
            return false;
        total += p;
    }
    return true;
}

template <typename T>
bool DecodeDepositPayload(const std::vector<unsigned char>& vch, T& payload)
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

template bool DecodeDepositPayload<DepositOriginate>(const std::vector<unsigned char>&, DepositOriginate&);
template bool DecodeDepositPayload<DepositTransfer>(const std::vector<unsigned char>&, DepositTransfer&);
template bool DecodeDepositPayload<DepositWithdraw>(const std::vector<unsigned char>&, DepositWithdraw&);
template bool DecodeDepositPayload<DepositClaim>(const std::vector<unsigned char>&, DepositClaim&);

static bool IsValidDepositPubKey(const std::vector<unsigned char>& vch)
{
    if (vch.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE)
        return false;
    CPubKey pubkey(vch);
    return pubkey.IsFullyValid();
}

/** vout[0..nReceipts-1] must each be a dust-valued P2PKH receipt output. */
static bool CheckDepositReceiptOutputs(const CTransaction& tx, size_t nReceipts, CValidationState& state)
{
    if (nReceipts == 0 || nReceipts > MAX_DEPOSIT_OUTPUTS)
        return state.DoS(100, false, REJECT_INVALID, "bad-deposit-receipt-count");
    if (tx.vout.size() < nReceipts)
        return state.DoS(100, false, REJECT_INVALID, "bad-deposit-vout-size");
    for (size_t i = 0; i < nReceipts; i++) {
        if (tx.vout[i].nValue != DEPOSIT_DUST_VALUE)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-output-value");
        if (!IsDepositP2PKH(tx.vout[i].scriptPubKey))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-output-script");
    }
    return true;
}

bool CheckDepositTransactionShape(const CTransaction& tx, CValidationState& state)
{
    if (tx.IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-deposit-coinbase");
    if (tx.nDepositOp < DEPOSIT_OP_ORIGINATE || tx.nDepositOp > DEPOSIT_OP_CLAIM)
        return state.DoS(100, false, REJECT_INVALID, "bad-deposit-op");

    // Up to 100 receipts x (u64 + 2x u32) + M approver sigs; bounded above worst.
    if (tx.vchDepositPayload.size() > 32768)
        return state.DoS(100, false, REJECT_INVALID, "bad-deposit-payload-oversize");

    if (tx.nDepositOp == DEPOSIT_OP_ORIGINATE) {
        DepositOriginate org;
        if (!DecodeDepositPayload(tx.vchDepositPayload, org))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-originate-payload");

        // Parallel arrays: one (principal, rate, maturity) per receipt output.
        const size_t n = org.vPrincipal.size();
        if (n == 0 || n > MAX_DEPOSIT_OUTPUTS ||
                org.vRateBps.size() != n || org.vMaturityHeight.size() != n)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-originate-arrays");
        uint64_t total = 0;
        if (!SumDepositPrincipal(org.vPrincipal, total))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-originate-principal");
        // maturity > origination (term > 0) and the term bound are CONTEXTUAL
        // (they need this block's height) - checked in CheckDepositOperation.
        if (!CheckDepositReceiptOutputs(tx, n, state))
            return false;

        // Approver arrays: non-empty, ascending, sized. Ranges vs the partner set
        // + the ECDSA are contextual.
        if (org.vApproverIndex.empty() || org.vApproverIndex.size() != org.vApproverSig.size())
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-originate-approvers");
        for (size_t i = 0; i < org.vApproverIndex.size(); i++) {
            if (i > 0 && org.vApproverIndex[i] <= org.vApproverIndex[i - 1])
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-originate-approvers");
            if (org.vApproverSig[i].empty() || org.vApproverSig[i].size() > 80)
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-originate-approvers");
        }
    }
    else if (tx.nDepositOp == DEPOSIT_OP_TRANSFER) {
        DepositTransfer xfer;
        if (!DecodeDepositPayload(tx.vchDepositPayload, xfer))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-transfer-payload");
        if (xfer.nPrincipal == 0 || xfer.nPrincipal > (uint64_t)MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-transfer-principal");
        // Exactly one receipt output to the new holder (dust P2PKH).
        if (!CheckDepositReceiptOutputs(tx, 1, state))
            return false;
        if (!IsValidDepositPubKey(xfer.vchSenderPubKey) ||
                xfer.vchSenderSig.empty() || xfer.vchSenderSig.size() > 80)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-transfer-sig-shape");
    }
    else if (tx.nDepositOp == DEPOSIT_OP_WITHDRAW) {
        DepositWithdraw wd;
        if (!DecodeDepositPayload(tx.vchDepositPayload, wd))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-withdraw-payload");
        if (tx.vout.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-withdraw-vout");
        if (!IsValidDepositPubKey(wd.vchHolderPubKey) ||
                wd.vchHolderSig.empty() || wd.vchHolderSig.size() > 80)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-withdraw-sig-shape");
    }
    else { // DEPOSIT_OP_CLAIM
        DepositClaim clm;
        if (!DecodeDepositPayload(tx.vchDepositPayload, clm))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-claim-payload");
        if (tx.vout.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-claim-vout");
        if (!IsValidDepositPubKey(clm.vchHolderPubKey) ||
                clm.vchHolderSig.empty() || clm.vchHolderSig.size() > 80)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-claim-sig-shape");
    }

    return true;
}
