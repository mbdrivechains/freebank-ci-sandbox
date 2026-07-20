// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UNDO_H
#define BITCOIN_UNDO_H

#include <compressor.h>
#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <serialize.h>

/** Undo information for a CTxIn
 *
 *  Contains the prevout's CTxOut being spent, and its metadata as well
 *  (coinbase or not, height). The serialization contains a dummy value of
 *  zero. This is be compatible with older versions which expect to see
 *  the transaction version there.
 */
class TxInUndoSerializer
{
    const Coin* txout;

public:
    template<typename Stream>
    void Serialize(Stream &s) const {
        ::Serialize(s, VARINT(txout->nHeight * 2 + (txout->fCoinBase ? 1 : 0)));
        if (txout->nHeight > 0) {
            // Required to maintain compatibility with older undo format.
            ::Serialize(s, (unsigned char)0);
        }
        ::Serialize(s, CTxOutCompressor(REF(txout->out)));
        // The asset / bill tags must survive a disconnect: without them
        // restored coins lose their consensus protection (and the bill
        // endorse-undo cannot locate the prior title outpoint)
        ::Serialize(s, txout->fBitAsset);
        ::Serialize(s, txout->fBitAssetControl);
        ::Serialize(s, txout->nAssetID);
        ::Serialize(s, txout->fBill);
        ::Serialize(s, txout->fBillEscrow);
        ::Serialize(s, txout->nBillID);
        ::Serialize(s, txout->fHouseEscrow);
        ::Serialize(s, txout->nHouseID);
        ::Serialize(s, txout->fNote);
        ::Serialize(s, txout->nNoteUnits);
        ::Serialize(s, txout->nDemandHeight);
        // Deposit receipt terms (Phase 3.8) must survive a disconnect too, or a
        // reorg-restored receipt loses its principal/rate/maturity.
        ::Serialize(s, txout->fDeposit);
        ::Serialize(s, txout->nDepositPrincipal);
        ::Serialize(s, txout->nDepositRateBps);
        ::Serialize(s, txout->nDepositMaturityHeight);
        ::Serialize(s, txout->nDepositOriginationHeight);
        // Pool custody / LP tags (Phase 3.7) must survive a disconnect, or a
        // reorg-restored escrow coin re-enters the UTXO set anyone-can-spend.
        ::Serialize(s, txout->fPoolEscrow);
        ::Serialize(s, txout->fLpShare);
        ::Serialize(s, txout->nLpUnits);
    }

    explicit TxInUndoSerializer(const Coin* coin) : txout(coin) {}
};

class TxInUndoDeserializer
{
    Coin* txout;

public:
    template<typename Stream>
    void Unserialize(Stream &s) {
        unsigned int nCode = 0;
        ::Unserialize(s, VARINT(nCode));
        txout->nHeight = nCode / 2;
        txout->fCoinBase = nCode & 1;
        if (txout->nHeight > 0) {
            // Old versions stored the version number for the last spend of
            // a transaction's outputs. Non-final spends were indicated with
            // height = 0.
            int nVersionDummy;
            ::Unserialize(s, VARINT(nVersionDummy));
        }
        ::Unserialize(s, REF(CTxOutCompressor(REF(txout->out))));
        ::Unserialize(s, txout->fBitAsset);
        ::Unserialize(s, txout->fBitAssetControl);
        ::Unserialize(s, txout->nAssetID);
        ::Unserialize(s, txout->fBill);
        ::Unserialize(s, txout->fBillEscrow);
        ::Unserialize(s, txout->nBillID);
        ::Unserialize(s, txout->fHouseEscrow);
        ::Unserialize(s, txout->nHouseID);
        ::Unserialize(s, txout->fNote);
        ::Unserialize(s, txout->nNoteUnits);
        ::Unserialize(s, txout->nDemandHeight);
        ::Unserialize(s, txout->fDeposit);
        ::Unserialize(s, txout->nDepositPrincipal);
        ::Unserialize(s, txout->nDepositRateBps);
        ::Unserialize(s, txout->nDepositMaturityHeight);
        ::Unserialize(s, txout->nDepositOriginationHeight);
        ::Unserialize(s, txout->fPoolEscrow);
        ::Unserialize(s, txout->fLpShare);
        ::Unserialize(s, txout->nLpUnits);
    }

    explicit TxInUndoDeserializer(Coin* coin) : txout(coin) {}
};

static const size_t MIN_TRANSACTION_INPUT_WEIGHT = WITNESS_SCALE_FACTOR * ::GetSerializeSize(CTxIn(), SER_NETWORK, PROTOCOL_VERSION);
static const size_t MAX_INPUTS_PER_BLOCK = MAX_BLOCK_WEIGHT / MIN_TRANSACTION_INPUT_WEIGHT;

/** Undo information for a CTransaction */
class CTxUndo
{
public:
    // undo information for all txins
    std::vector<Coin> vprevout;

    template <typename Stream>
    void Serialize(Stream& s) const {
        // TODO: avoid reimplementing vector serializer
        uint64_t count = vprevout.size();
        ::Serialize(s, COMPACTSIZE(REF(count)));
        for (const auto& prevout : vprevout) {
            ::Serialize(s, REF(TxInUndoSerializer(&prevout)));
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        // TODO: avoid reimplementing vector deserializer
        uint64_t count = 0;
        ::Unserialize(s, COMPACTSIZE(count));
        if (count > MAX_INPUTS_PER_BLOCK) {
            throw std::ios_base::failure("Too many input undo records");
        }
        vprevout.resize(count);
        for (auto& prevout : vprevout) {
            ::Unserialize(s, REF(TxInUndoDeserializer(&prevout)));
        }
    }
};

/** Undo information for a CBlock */
class CBlockUndo
{
public:
    std::vector<CTxUndo> vtxundo; // for all but the coinbase

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vtxundo);
    }
};

#endif // BITCOIN_UNDO_H
