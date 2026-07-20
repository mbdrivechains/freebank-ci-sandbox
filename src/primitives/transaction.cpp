// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <hash.h>
#include <tinyformat.h>
#include <utilstrencodings.h>

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime), ticker(tx.ticker), headline(tx.headline), payload(tx.payload), nBillOp(tx.nBillOp), vchBillPayload(tx.vchBillPayload), nHouseOp(tx.nHouseOp), vchHousePayload(tx.vchHousePayload), nNoteOp(tx.nNoteOp), vchNotePayload(tx.vchNotePayload), nDepositOp(tx.nDepositOp), vchDepositPayload(tx.vchDepositPayload), nPoolOp(tx.nPoolOp), vchPoolPayload(tx.vchPoolPayload) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::GetWitnessHash() const
{
    if (!HasWitness()) {
        return GetHash();
    }
    return SerializeHash(*this, SER_GETHASH, 0);
}

/* For backward compatibility, the hash is initialized to 0. TODO: remove the need for this default constructor entirely. */
CTransaction::CTransaction() : vin(), vout(), nVersion(CTransaction::CURRENT_VERSION), nLockTime(0), ticker(""), headline(""), payload(), nBillOp(0), vchBillPayload(), nHouseOp(0), vchHousePayload(), nNoteOp(0), vchNotePayload(), nDepositOp(0), vchDepositPayload(), nPoolOp(0), vchPoolPayload(), hash() {}
CTransaction::CTransaction(const CMutableTransaction &tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime), ticker(tx.ticker), headline(tx.headline), payload(tx.payload), nBillOp(tx.nBillOp), vchBillPayload(tx.vchBillPayload), nHouseOp(tx.nHouseOp), vchHousePayload(tx.vchHousePayload), nNoteOp(tx.nNoteOp), vchNotePayload(tx.vchNotePayload), nDepositOp(tx.nDepositOp), vchDepositPayload(tx.vchDepositPayload), nPoolOp(tx.nPoolOp), vchPoolPayload(tx.vchPoolPayload), hash(ComputeHash()) {}
CTransaction::CTransaction(CMutableTransaction &&tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), nVersion(tx.nVersion), nLockTime(tx.nLockTime), ticker(tx.ticker), headline(tx.headline), payload(tx.payload), nBillOp(tx.nBillOp), vchBillPayload(std::move(tx.vchBillPayload)), nHouseOp(tx.nHouseOp), vchHousePayload(std::move(tx.vchHousePayload)), nNoteOp(tx.nNoteOp), vchNotePayload(std::move(tx.vchNotePayload)), nDepositOp(tx.nDepositOp), vchDepositPayload(std::move(tx.vchDepositPayload)), nPoolOp(tx.nPoolOp), vchPoolPayload(std::move(tx.vchPoolPayload)), hash(ComputeHash()) {}

CAmount CTransaction::GetValueOut() const
{
    bool fBitAsset = nVersion == TRANSACTION_BITASSET_CREATE_VERSION;

    // Skip the controller and genesis output of a BitAsset creation
    std::vector<CTxOut>::const_iterator it;
    if (fBitAsset && vout.size() >= 2)
        it = vout.begin() + 2;
    else
        it = vout.begin();

    CAmount nValueOut = 0;
    for (; it != vout.end(); it++) {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nValueOut;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (const auto& tx_in : vin)
        str += "    " + tx_in.ToString() + "\n";
    for (const auto& tx_in : vin)
        str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (const auto& tx_out : vout)
        str += "    " + tx_out.ToString() + "\n";
    return str;
}
