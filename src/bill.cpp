// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bill.h>

#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <pubkey.h>
#include <script/standard.h>
#include <streams.h>
#include <version.h>

uint256 BillIDFromBody(const std::vector<unsigned char>& vchBody)
{
    uint256 hash;
    CSHA256().Write(vchBody.data(), vchBody.size()).Finalize(hash.begin());
    return hash;
}

uint256 BillIssueSigHash(const uint256& billID, const CAmount& amount, const CAmount& amountEscrow, uint32_t nMaturityHeight, uint32_t nGraceBlocks, const std::vector<unsigned char>& vchDrawerPubKey, const std::vector<unsigned char>& vchAcceptorPubKey, const std::vector<unsigned char>& vchHolderPubKey)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankBill/issue");
    ss << billID;
    ss << amount;
    ss << amountEscrow;   // binds the posted bond -> no token-escrow replay
    ss << nMaturityHeight;
    ss << nGraceBlocks;
    ss << vchDrawerPubKey;
    ss << vchAcceptorPubKey;
    ss << vchHolderPubKey;
    return ss.GetHash();
}

uint256 BillEndorseSigHash(const uint256& billID, const std::vector<unsigned char>& vchTo, uint32_t nAtHeight)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankBill/endorse");
    ss << billID;
    ss << vchTo;
    ss << nAtHeight;
    return ss.GetHash();
}

uint256 BillHashOutputs(const CTransaction& tx)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (const CTxOut& out : tx.vout)
        ss << out;
    return ss.GetHash();
}

uint256 BillRetireSigHash(const uint256& billID, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankBill/retire");
    ss << billID;
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 BillClaimSigHash(const uint256& billID, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankBill/claim");
    ss << billID;
    ss << hashOutputs;
    return ss.GetHash();
}

CScript BillEscrowScript(const uint256& billID)
{
    return CScript() << std::vector<unsigned char>(billID.begin(), billID.end()) << OP_DROP << OP_TRUE;
}

bool IsBillEscrowScript(const CScript& script)
{
    // <32-byte push> OP_DROP OP_TRUE
    return script.size() == 35 && script[0] == 0x20 &&
           script[33] == OP_DROP && script[34] == OP_TRUE;
}

CScript BillScriptForPubKey(const std::vector<unsigned char>& vchPubKey)
{
    CPubKey pubkey(vchPubKey);
    return GetScriptForDestination(pubkey.GetID());
}

template <typename T>
bool DecodeBillPayload(const std::vector<unsigned char>& vch, T& payload)
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

template bool DecodeBillPayload<BillIssue>(const std::vector<unsigned char>&, BillIssue&);
template bool DecodeBillPayload<BillEndorse>(const std::vector<unsigned char>&, BillEndorse&);
template bool DecodeBillPayload<BillRetire>(const std::vector<unsigned char>&, BillRetire&);
template bool DecodeBillPayload<BillClaim>(const std::vector<unsigned char>&, BillClaim&);

static bool IsValidBillPubKey(const std::vector<unsigned char>& vch)
{
    if (vch.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE)
        return false;

    CPubKey pubkey(vch);
    return pubkey.IsFullyValid();
}

bool CheckBillTransactionShape(const CTransaction& tx, CValidationState& state)
{
    if (tx.IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-bill-coinbase");

    if (tx.nBillOp < BILL_OP_ISSUE || tx.nBillOp > BILL_OP_CLAIM)
        return state.DoS(100, false, REJECT_INVALID, "bad-bill-op");

    if (tx.vchBillPayload.size() > MAX_BILL_BODY_BYTES + 1024)
        return state.DoS(100, false, REJECT_INVALID, "bad-bill-payload-oversize");

    if (tx.nBillOp == BILL_OP_ISSUE) {
        BillIssue issue;
        if (!DecodeBillPayload(tx.vchBillPayload, issue))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-payload");

        if (issue.vchEncryptedBody.empty() || issue.vchEncryptedBody.size() > MAX_BILL_BODY_BYTES)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-body");
        if (issue.amount <= 0 || issue.amount > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-amount");
        if (issue.nMaturityHeight == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-maturity");
        if (issue.nGraceBlocks > MAX_BILL_GRACE_BLOCKS)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-grace");
        if (!IsValidBillPubKey(issue.vchDrawerPubKey) ||
                !IsValidBillPubKey(issue.vchAcceptorPubKey) ||
                !IsValidBillPubKey(issue.vchHolderPubKey))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-pubkey");

        // vout[0] = title to the initial holder, vout[1] = the escrow bond
        if (tx.vout.size() < 2)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-vout-size");
        if (tx.vout[0].nValue != BILL_TITLE_VALUE ||
                tx.vout[0].scriptPubKey != BillScriptForPubKey(issue.vchHolderPubKey))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-title");

        const uint256 billID = BillIDFromBody(issue.vchEncryptedBody);
        if (tx.vout[1].nValue <= 0 ||
                tx.vout[1].scriptPubKey != BillEscrowScript(billID))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-escrow");

        // NB: the drawer/acceptor ECDSA verifies are deliberately NOT done here.
        // CheckBillTransactionShape runs in the context-free CheckTransaction
        // path (before inputs/fees are checked), so verifying signatures here
        // would let a stream of orphan v11 txs force free CPU. The two verifies
        // run in CheckBillOperation (validation.cpp), after CheckTxInputs.
    }
    else
    if (tx.nBillOp == BILL_OP_ENDORSE) {
        BillEndorse endorse;
        if (!DecodeBillPayload(tx.vchBillPayload, endorse))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-endorse-payload");

        if (!IsValidBillPubKey(endorse.endorsement.vchFrom) ||
                !IsValidBillPubKey(endorse.endorsement.vchTo))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-endorse-pubkey");

        // vout[0] = the title moving to the endorsee. The endorsement
        // signature needs the bill hash, so it is checked contextually.
        if (tx.vout.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-endorse-vout-size");
        if (tx.vout[0].nValue != BILL_TITLE_VALUE ||
                tx.vout[0].scriptPubKey != BillScriptForPubKey(endorse.endorsement.vchTo))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-endorse-title");
    }
    else
    if (tx.nBillOp == BILL_OP_RETIRE) {
        BillRetire retire;
        if (!DecodeBillPayload(tx.vchBillPayload, retire))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-retire-payload");
    }
    else
    if (tx.nBillOp == BILL_OP_CLAIM) {
        BillClaim claim;
        if (!DecodeBillPayload(tx.vchBillPayload, claim))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-claim-payload");
    }

    return true;
}

CAmount BillValuePaidTo(const CTransaction& tx, const std::vector<unsigned char>& vchPubKey)
{
    const CScript script = BillScriptForPubKey(vchPubKey);

    CAmount nValue = 0;
    for (const CTxOut& out : tx.vout) {
        if (out.scriptPubKey == script)
            nValue += out.nValue;
    }
    return nValue;
}

CAmount BillEndorseFeeFloor(size_t nLen)
{
    if (nLen <= BILL_ENDORSE_SOFT_CAP)
        return CAmount(0);

    size_t nShift = nLen - BILL_ENDORSE_SOFT_CAP;
    if (nShift > 30)
        nShift = 30;

    return BILL_ENDORSE_BASE_FEE << nShift;
}
