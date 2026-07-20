// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COINS_H
#define BITCOIN_COINS_H

#include <primitives/transaction.h>
#include <compressor.h>
#include <core_memusage.h>
#include <hash.h>
#include <memusage.h>
#include <serialize.h>
#include <uint256.h>

#include <assert.h>
#include <stdint.h>

#include <unordered_map>

/**
 * A UTXO entry.
 *
 * Serialized format:
 * - VARINT((coinbase ? 1 : 0) | (height << 1))
 * - the non-spent CTxOut (via CTxOutCompressor)
 */
class Coin
{
public:
    //! unspent transaction output
    CTxOut out;

    //! whether containing transaction was a coinbase
    unsigned int fCoinBase : 1;

    //! at which height this containing transaction was included in the active block chain
    uint32_t nHeight : 31;

    // TODO instead of tracking this, we could just check if the asset ID
    // is > 0 (the default bitcoin asset reserves the first ID)
    //! Is this a BitAsset?
    bool fBitAsset;

    //! Is this a BitAsset controller?
    bool fBitAssetControl;

    uint32_t nAssetID;

    //! Is this a bill title (ownership) output?
    bool fBill;

    //! Is this a bill escrow output?
    bool fBillEscrow;

    uint32_t nBillID;

    //! Is this a house pledge escrow output?
    bool fHouseEscrow;

    uint32_t nHouseID;

    //! Is this a note (per-house credit claim) output? Reuses nHouseID for the
    //! class; nNoteUnits carries the claim amount (NOT base-coin - the coin's
    //! nValue is dust).
    bool fNote;

    uint64_t nNoteUnits;

    //! Height at which the holder DEMANDED payment of this note (Phase 3.5
    //! option clause). 0 = not demanded. Interest accrues from this height -
    //! the historical rule is "5% per annum from the date of demand" - and the
    //! clock survives a TRANSFER, so a queued holder who needs out early can
    //! sell at a market discount instead of being trapped.
    uint32_t nDemandHeight;

    //! Is this a term-deposit receipt (Phase 3.8) output? Reuses nHouseID for the
    //! house; the immutable receipt terms ride alongside (the coin's nValue is
    //! dust - the claim is principal + accrued, not base value).
    bool fDeposit;
    uint64_t nDepositPrincipal;
    uint32_t nDepositRateBps;
    uint32_t nDepositMaturityHeight;
    uint32_t nDepositOriginationHeight;

    //! Is this a pool escrow output (Phase 3.7 AMM)? Reuses nHouseID for the
    //! pool (nPoolID == nHouseID, one pool per house). The note-side custody
    //! coin is DUAL-tagged fNote + fPoolEscrow (its units stay a real
    //! outstanding liability); the BTX-side coin carries the sats reserve.
    bool fPoolEscrow;

    //! Is this an LP-share output? Reuses nHouseID for the pool; nLpUnits
    //! carries the share amount (the coin's nValue is dust).
    bool fLpShare;
    uint64_t nLpUnits;

    //! construct a Coin from a CTxOut and height/coinbase information.
    Coin(CTxOut&& outIn, int nHeightIn, bool fCoinBaseIn, bool fBitAssetIn, bool fBitAssetControlIn, uint32_t nAssetIDIn) : out(std::move(outIn)), fCoinBase(fCoinBaseIn), nHeight(nHeightIn), fBitAsset(fBitAssetIn), fBitAssetControl(fBitAssetControlIn), nAssetID(nAssetIDIn), fBill(false), fBillEscrow(false), nBillID(0), fHouseEscrow(false), nHouseID(0), fNote(false), nNoteUnits(0), nDemandHeight(0), fDeposit(false), nDepositPrincipal(0), nDepositRateBps(0), nDepositMaturityHeight(0), nDepositOriginationHeight(0), fPoolEscrow(false), fLpShare(false), nLpUnits(0) {}
    Coin(const CTxOut& outIn, int nHeightIn, bool fCoinBaseIn, bool fBitAssetIn, bool fBitAssetControlIn, uint32_t nAssetIDIn) : out(outIn), fCoinBase(fCoinBaseIn), nHeight(nHeightIn), fBitAsset(fBitAssetIn), fBitAssetControl(fBitAssetControlIn), nAssetID(nAssetIDIn), fBill(false), fBillEscrow(false), nBillID(0), fHouseEscrow(false), nHouseID(0), fNote(false), nNoteUnits(0), nDemandHeight(0), fDeposit(false), nDepositPrincipal(0), nDepositRateBps(0), nDepositMaturityHeight(0), nDepositOriginationHeight(0), fPoolEscrow(false), fLpShare(false), nLpUnits(0) {}

    void SetBill(bool fEscrowIn, uint32_t nBillIDIn) {
        fBill = !fEscrowIn;
        fBillEscrow = fEscrowIn;
        nBillID = nBillIDIn;
    }

    void SetHouseEscrow(uint32_t nHouseIDIn) {
        fHouseEscrow = true;
        nHouseID = nHouseIDIn;
    }

    void SetNote(uint32_t nHouseIDIn, uint64_t nUnitsIn, uint32_t nDemandHeightIn = 0) {
        fNote = true;
        nHouseID = nHouseIDIn;
        nNoteUnits = nUnitsIn;
        nDemandHeight = nDemandHeightIn;
    }

    void SetDeposit(uint32_t nHouseIDIn, uint64_t nPrincipalIn, uint32_t nRateBpsIn,
                    uint32_t nMaturityHeightIn, uint32_t nOriginationHeightIn) {
        fDeposit = true;
        nHouseID = nHouseIDIn;
        nDepositPrincipal = nPrincipalIn;
        nDepositRateBps = nRateBpsIn;
        nDepositMaturityHeight = nMaturityHeightIn;
        nDepositOriginationHeight = nOriginationHeightIn;
    }

    void SetPoolEscrow(uint32_t nPoolIDIn) {
        fPoolEscrow = true;
        nHouseID = nPoolIDIn;
    }

    void SetLpShare(uint32_t nPoolIDIn, uint64_t nUnitsIn) {
        fLpShare = true;
        nHouseID = nPoolIDIn;
        nLpUnits = nUnitsIn;
    }

    void Clear() {
        out.SetNull();
        fCoinBase = false;
        nHeight = 0;
        fBitAsset = false;
        fBitAssetControl = false;
        nAssetID = 0;
        fBill = false;
        fBillEscrow = false;
        nBillID = 0;
        fHouseEscrow = false;
        nHouseID = 0;
        fNote = false;
        nNoteUnits = 0;
        nDemandHeight = 0;
        fDeposit = false;
        nDepositPrincipal = 0;
        nDepositRateBps = 0;
        nDepositMaturityHeight = 0;
        nDepositOriginationHeight = 0;
        fPoolEscrow = false;
        fLpShare = false;
        nLpUnits = 0;
    }

    //! empty constructor
    Coin() : fCoinBase(false), nHeight(0), fBitAsset(false), fBitAssetControl(false), nAssetID(0), fBill(false), fBillEscrow(false), nBillID(0), fHouseEscrow(false), nHouseID(0), fNote(false), nNoteUnits(0), nDemandHeight(0), fDeposit(false), nDepositPrincipal(0), nDepositRateBps(0), nDepositMaturityHeight(0), nDepositOriginationHeight(0), fPoolEscrow(false), fLpShare(false), nLpUnits(0) { }

    bool IsCoinBase() const {
        return fCoinBase;
    }

    bool IsBitAsset() const {
        return fBitAsset;
    }

    bool IsBitAssetController() const {
        return fBitAssetControl;
    }

    uint32_t GetAssetID() const {
        return nAssetID;
    }

    template<typename Stream>
    void Serialize(Stream &s) const {
        assert(!IsSpent());
        uint32_t code = nHeight * 2 + fCoinBase;
        ::Serialize(s, VARINT(code));
        ::Serialize(s, CTxOutCompressor(REF(out)));
        ::Serialize(s, fBitAsset);
        ::Serialize(s, fBitAssetControl);
        ::Serialize(s, nAssetID);
        ::Serialize(s, fBill);
        ::Serialize(s, fBillEscrow);
        ::Serialize(s, nBillID);
        ::Serialize(s, fHouseEscrow);
        ::Serialize(s, nHouseID);
        ::Serialize(s, fNote);
        ::Serialize(s, nNoteUnits);
        ::Serialize(s, nDemandHeight);
        ::Serialize(s, fDeposit);
        ::Serialize(s, nDepositPrincipal);
        ::Serialize(s, nDepositRateBps);
        ::Serialize(s, nDepositMaturityHeight);
        ::Serialize(s, nDepositOriginationHeight);
        ::Serialize(s, fPoolEscrow);
        ::Serialize(s, fLpShare);
        ::Serialize(s, nLpUnits);
    }

    template<typename Stream>
    void Unserialize(Stream &s) {
        uint32_t code = 0;
        ::Unserialize(s, VARINT(code));
        nHeight = code >> 1;
        fCoinBase = code & 1;
        ::Unserialize(s, REF(CTxOutCompressor(out)));
        ::Unserialize(s, fBitAsset);
        ::Unserialize(s, fBitAssetControl);
        ::Unserialize(s, nAssetID);
        ::Unserialize(s, fBill);
        ::Unserialize(s, fBillEscrow);
        ::Unserialize(s, nBillID);
        ::Unserialize(s, fHouseEscrow);
        ::Unserialize(s, nHouseID);
        ::Unserialize(s, fNote);
        ::Unserialize(s, nNoteUnits);
        ::Unserialize(s, nDemandHeight);
        ::Unserialize(s, fDeposit);
        ::Unserialize(s, nDepositPrincipal);
        ::Unserialize(s, nDepositRateBps);
        ::Unserialize(s, nDepositMaturityHeight);
        ::Unserialize(s, nDepositOriginationHeight);
        ::Unserialize(s, fPoolEscrow);
        ::Unserialize(s, fLpShare);
        ::Unserialize(s, nLpUnits);
    }

    bool IsSpent() const {
        return out.IsNull();
    }

    size_t DynamicMemoryUsage() const {
        return memusage::DynamicUsage(out.scriptPubKey);
    }
};

class SaltedOutpointHasher
{
private:
    /** Salt */
    const uint64_t k0, k1;

public:
    SaltedOutpointHasher();

    /**
     * This *must* return size_t. With Boost 1.46 on 32-bit systems the
     * unordered_map will behave unpredictably if the custom hasher returns a
     * uint64_t, resulting in failures when syncing the chain (#4634).
     */
    size_t operator()(const COutPoint& id) const {
        return SipHashUint256Extra(k0, k1, id.hash, id.n);
    }
};

struct CCoinsCacheEntry
{
    Coin coin; // The actual cached data.
    unsigned char flags;

    enum Flags {
        DIRTY = (1 << 0), // This cache entry is potentially different from the version in the parent view.
        FRESH = (1 << 1), // The parent view does not have this entry (or it is pruned).
        /* Note that FRESH is a performance optimization with which we can
         * erase coins that are fully spent if we know we do not need to
         * flush the changes to the parent cache.  It is always safe to
         * not mark FRESH if that condition is not guaranteed.
         */
    };

    CCoinsCacheEntry() : flags(0) {}
    explicit CCoinsCacheEntry(Coin&& coin_) : coin(std::move(coin_)), flags(0) {}
};

typedef std::unordered_map<COutPoint, CCoinsCacheEntry, SaltedOutpointHasher> CCoinsMap;

/** Cursor for iterating over CoinsView state */
class CCoinsViewCursor
{
public:
    CCoinsViewCursor(const uint256 &hashBlockIn): hashBlock(hashBlockIn) {}
    virtual ~CCoinsViewCursor() {}

    virtual bool GetKey(COutPoint &key) const = 0;
    virtual bool GetValue(Coin &coin) const = 0;
    virtual unsigned int GetValueSize() const = 0;

    virtual bool Valid() const = 0;
    virtual void Next() = 0;

    //! Get best block at the time this cursor was created
    const uint256 &GetBestBlock() const { return hashBlock; }
private:
    uint256 hashBlock;
};

/** Abstract view on the open txout dataset. */
class CCoinsView
{
public:
    /** Retrieve the Coin (unspent transaction output) for a given outpoint.
     *  Returns true only when an unspent coin was found, which is returned in coin.
     *  When false is returned, coin's value is unspecified.
     */
    virtual bool GetCoin(const COutPoint &outpoint, Coin &coin) const;

    //! Just check whether a given outpoint is unspent.
    virtual bool HaveCoin(const COutPoint &outpoint) const;

    //! Retrieve the block hash whose state this CCoinsView currently represents
    virtual uint256 GetBestBlock() const;

    //! Retrieve the range of blocks that may have been only partially written.
    //! If the database is in a consistent state, the result is the empty vector.
    //! Otherwise, a two-element vector is returned consisting of the new and
    //! the old block hash, in that order.
    virtual std::vector<uint256> GetHeadBlocks() const;

    //! Do a bulk modification (multiple Coin changes + BestBlock change).
    //! The passed mapCoins can be modified.
    virtual bool BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock);

    //! Get a cursor to iterate over the whole state
    virtual CCoinsViewCursor *Cursor() const;

    //! As we use CCoinsViews polymorphically, have a virtual destructor
    virtual ~CCoinsView() {}

    //! Estimate database size (0 if not implemented)
    virtual size_t EstimateSize() const { return 0; }
};


/** CCoinsView backed by another CCoinsView */
class CCoinsViewBacked : public CCoinsView
{
protected:
    CCoinsView *base;

public:
    CCoinsViewBacked(CCoinsView *viewIn);
    bool GetCoin(const COutPoint &outpoint, Coin &coin) const override;
    bool HaveCoin(const COutPoint &outpoint) const override;
    uint256 GetBestBlock() const override;
    std::vector<uint256> GetHeadBlocks() const override;
    void SetBackend(CCoinsView &viewIn);
    bool BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) override;
    CCoinsViewCursor *Cursor() const override;
    size_t EstimateSize() const override;
};


/** CCoinsView that adds a memory cache for transactions to another CCoinsView */
class CCoinsViewCache : public CCoinsViewBacked
{
protected:
    /**
     * Make mutable so that we can "fill the cache" even from Get-methods
     * declared as "const".
     */
    mutable uint256 hashBlock;
    mutable CCoinsMap cacheCoins;

    /* Cached dynamic memory usage for the inner Coin objects. */
    mutable size_t cachedCoinsUsage;

public:
    CCoinsViewCache(CCoinsView *baseIn);

    /**
     * By deleting the copy constructor, we prevent accidentally using it when one intends to create a cache on top of a base cache.
     */
    CCoinsViewCache(const CCoinsViewCache &) = delete;

    // Standard CCoinsView methods
    bool GetCoin(const COutPoint &outpoint, Coin &coin) const override;
    bool HaveCoin(const COutPoint &outpoint) const override;
    uint256 GetBestBlock() const override;
    void SetBestBlock(const uint256 &hashBlock);
    bool BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) override;
    CCoinsViewCursor* Cursor() const override {
        throw std::logic_error("CCoinsViewCache cursor iteration not supported.");
    }

    /**
     * Check if we have the given utxo already loaded in this cache.
     * The semantics are the same as HaveCoin(), but no calls to
     * the backing CCoinsView are made.
     */
    bool HaveCoinInCache(const COutPoint &outpoint) const;

    /**
     * Return a reference to Coin in the cache, or a pruned one if not found. This is
     * more efficient than GetCoin.
     *
     * Generally, do not hold the reference returned for more than a short scope.
     * While the current implementation allows for modifications to the contents
     * of the cache while holding the reference, this behavior should not be relied
     * on! To be safe, best to not hold the returned reference through any other
     * calls to this cache.
     */
    const Coin& AccessCoin(const COutPoint &output) const;

    /**
     * Add a coin. Set potential_overwrite to true if a non-pruned version may
     * already exist.
     */
    void AddCoin(const COutPoint& outpoint, Coin&& coin, bool potential_overwrite);

    /**
     * Spend a coin. Pass moveto in order to get the deleted data.
     * If no unspent output exists for the passed outpoint, this call
     * has no effect.
     */
    bool SpendCoin(const COutPoint &outpoint, bool& fBitAsset, bool& fBitAssetControl, uint32_t& nAssetID, Coin* moveto = nullptr);

    /**
     * Push the modifications applied to this cache to its base.
     * Failure to call this method before destruction will cause the changes to be forgotten.
     * If false is returned, the state of this cache (and its backing view) will be undefined.
     */
    bool Flush();

    /**
     * Removes the UTXO with the given outpoint from the cache, if it is
     * not modified.
     */
    void Uncache(const COutPoint &outpoint);

    //! Calculate the size of the cache (in number of transaction outputs)
    unsigned int GetCacheSize() const;

    //! Calculate the size of the cache (in bytes)
    size_t DynamicMemoryUsage() const;

    /**
     * Amount of bitcoins coming in to a transaction
     * Note that lightweight clients may not know anything besides the hash of previous transactions,
     * so may not be able to calculate this.
     *
     * @param[in] tx	transaction for which we are checking input total
     * @return	Sum of value of all inputs (scriptSigs)
     */
    CAmount GetValueIn(const CTransaction& tx) const;

    //! Check whether all prevouts of the transaction are present in the UTXO set represented by this view
    bool HaveInputs(const CTransaction& tx) const;

private:
    CCoinsMap::iterator FetchCoin(const COutPoint &outpoint) const;
};

//! Utility function to add all of a transaction's outputs to a cache.
// When check is false, this assumes that overwrites are only possible for coinbase transactions.
// When check is true, the underlying view may be queried to determine whether an addition is
// an overwrite.
// TODO: pass in a boolean to limit these possible overwrites to known
// (pre-BIP34) cases.
void AddCoins(CCoinsViewCache& cache, const CTransaction& tx, int nHeight, uint32_t nAssetID, const CAmount amountAssetIn, int nControlN = -1, uint32_t nNewAssetID = 0, uint32_t nBillID = 0, uint32_t nHouseID = 0, bool check = false);

//! Utility function to find any unspent output with a given txid.
// This function can be quite expensive because in the event of a transaction
// which is not found in the cache, it can cause up to MAX_OUTPUTS_PER_BLOCK
// lookups to database, so it should be used with care.
const Coin& AccessByTxid(const CCoinsViewCache& cache, const uint256& txid);

#endif // BITCOIN_COINS_H
