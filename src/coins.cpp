// Copyright (c) 2012-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>

#include <bill.h>
#include <deposit.h>
#include <house.h>
#include <note.h>
#include <pool.h>
#include <consensus/consensus.h>
#include <random.h>

bool CCoinsView::GetCoin(const COutPoint &outpoint, Coin &coin) const { return false; }
uint256 CCoinsView::GetBestBlock() const { return uint256(); }
std::vector<uint256> CCoinsView::GetHeadBlocks() const { return std::vector<uint256>(); }
bool CCoinsView::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) { return false; }
CCoinsViewCursor *CCoinsView::Cursor() const { return nullptr; }

bool CCoinsView::HaveCoin(const COutPoint &outpoint) const
{
    Coin coin;
    return GetCoin(outpoint, coin);
}

CCoinsViewBacked::CCoinsViewBacked(CCoinsView *viewIn) : base(viewIn) { }
bool CCoinsViewBacked::GetCoin(const COutPoint &outpoint, Coin &coin) const { return base->GetCoin(outpoint, coin); }
bool CCoinsViewBacked::HaveCoin(const COutPoint &outpoint) const { return base->HaveCoin(outpoint); }
uint256 CCoinsViewBacked::GetBestBlock() const { return base->GetBestBlock(); }
std::vector<uint256> CCoinsViewBacked::GetHeadBlocks() const { return base->GetHeadBlocks(); }
void CCoinsViewBacked::SetBackend(CCoinsView &viewIn) { base = &viewIn; }
bool CCoinsViewBacked::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) { return base->BatchWrite(mapCoins, hashBlock); }
CCoinsViewCursor *CCoinsViewBacked::Cursor() const { return base->Cursor(); }
size_t CCoinsViewBacked::EstimateSize() const { return base->EstimateSize(); }

SaltedOutpointHasher::SaltedOutpointHasher() : k0(GetRand(std::numeric_limits<uint64_t>::max())), k1(GetRand(std::numeric_limits<uint64_t>::max())) {}

CCoinsViewCache::CCoinsViewCache(CCoinsView *baseIn) : CCoinsViewBacked(baseIn), cachedCoinsUsage(0) {}

size_t CCoinsViewCache::DynamicMemoryUsage() const {
    return memusage::DynamicUsage(cacheCoins) + cachedCoinsUsage;
}

CCoinsMap::iterator CCoinsViewCache::FetchCoin(const COutPoint &outpoint) const {
    CCoinsMap::iterator it = cacheCoins.find(outpoint);
    if (it != cacheCoins.end())
        return it;
    Coin tmp;
    if (!base->GetCoin(outpoint, tmp))
        return cacheCoins.end();
    CCoinsMap::iterator ret = cacheCoins.emplace(std::piecewise_construct, std::forward_as_tuple(outpoint), std::forward_as_tuple(std::move(tmp))).first;
    if (ret->second.coin.IsSpent()) {
        // The parent only has an empty entry for this outpoint; we can consider our
        // version as fresh.
        ret->second.flags = CCoinsCacheEntry::FRESH;
    }
    cachedCoinsUsage += ret->second.coin.DynamicMemoryUsage();
    return ret;
}

bool CCoinsViewCache::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    if (it != cacheCoins.end()) {
        coin = it->second.coin;
        return !coin.IsSpent();
    }
    return false;
}

void CCoinsViewCache::AddCoin(const COutPoint &outpoint, Coin&& coin, bool possible_overwrite) {
    assert(!coin.IsSpent());
    if (coin.out.scriptPubKey.IsUnspendable()) return;
    CCoinsMap::iterator it;
    bool inserted;
    std::tie(it, inserted) = cacheCoins.emplace(std::piecewise_construct, std::forward_as_tuple(outpoint), std::tuple<>());
    bool fresh = false;
    if (!inserted) {
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
    }
    if (!possible_overwrite) {
        if (!it->second.coin.IsSpent()) {
            throw std::logic_error("Adding new coin that replaces non-pruned entry");
        }
        fresh = !(it->second.flags & CCoinsCacheEntry::DIRTY);
    }
    it->second.coin = std::move(coin);
    it->second.flags |= CCoinsCacheEntry::DIRTY | (fresh ? CCoinsCacheEntry::FRESH : 0);
    cachedCoinsUsage += it->second.coin.DynamicMemoryUsage();
}

void AddCoins(CCoinsViewCache& cache, const CTransaction &tx, int nHeight, uint32_t nAssetID, const CAmount amountAssetIn, int nControlN, uint32_t nNewAssetID, uint32_t nBillID, uint32_t nHouseID, bool check) {
    bool fCoinbase = tx.IsCoinBase();
    const uint256& txid = tx.GetHash();

    if (amountAssetIn > 0) {
        // One of the input coins is a BitAsset, coins adding up to the asset
        // input amount will be marked as BitAssets

        // Label BitAsset outputs until we account for all BitAsset input
        CAmount amountAssetOut = CAmount(0);
        for (size_t i = 0; i < tx.vout.size(); ++i) {
            bool overwrite = check ? cache.HaveCoin(COutPoint(txid, i)) : fCoinbase;
            bool fAsset = amountAssetIn > amountAssetOut;
            bool fControl = nControlN >= 0 && (int)i == nControlN;
            uint32_t nID = nNewAssetID ? nNewAssetID : nAssetID;
            cache.AddCoin(COutPoint(txid, i), Coin(tx.vout[i], nHeight, fCoinbase, fAsset, fControl, fAsset ? nID : 0), overwrite);
            if (fAsset)
                amountAssetOut += tx.vout[i].nValue;
        }
    }
    else
    {
        // The first two outputs of a BitAsset creation transaction are
        // 0: controller output
        // 1: genesis output
        // The rest are normal outputs
        bool fNewAsset = tx.nVersion == TRANSACTION_BITASSET_CREATE_VERSION;

        // Bill transactions tag the title / escrow outputs. Bill txs cannot
        // spend asset-colored inputs (bad-bill-asset-input), so they always
        // take this branch.
        bool fBillTx = tx.nVersion == TRANSACTION_BILL_VERSION && nBillID != 0;

        // House transactions tag pledge escrow outputs: REGISTER posts one per
        // partner at vout[0..N-1] (N from the payload), TOPUP / ADMIT at
        // vout[0]. House txs cannot spend asset-colored inputs
        // (bad-house-colored-input), so they always take this branch.
        bool fHouseTx = tx.nVersion == TRANSACTION_HOUSE_VERSION && nHouseID != 0;
        size_t nHousePledges = 0;
        if (fHouseTx && tx.nHouseOp == HOUSE_OP_REGISTER) {
            HouseRegister reg;
            if (DecodeHousePayload(tx.vchHousePayload, reg))
                nHousePledges = reg.vPartnerPubKey.size();
        }

        // Note transactions tag their new note outputs (fNote + nHouseID +
        // per-output nNoteUnits). Unlike houses, a note carries its house and
        // unit split in the PAYLOAD, so AddCoins is self-contained and tags
        // identically on ConnectBlock and RollforwardBlock with no threaded id
        // (sidestepping the positional-arg / stale-id regression class). MINT
        // and TRANSFER create note outputs at vout[0..vUnits-1]; REDEEM does not.
        bool fNoteTx = tx.nVersion == TRANSACTION_NOTE_VERSION;
        uint32_t nNoteHouse = 0;
        std::vector<uint64_t> vNoteUnits;
        // Demand height carried onto the new note outputs (3.5). DEMAND stamps
        // THIS block's height; TRANSFER carries the payload's value forward
        // (tx_verify has already forced it to equal the spent notes' height),
        // so a demanded note keeps its interest clock when it changes hands.
        uint32_t nNoteDemandHeight = 0;
        bool fClaimEscrowChange = false;
        uint32_t nClaimHouse = 0;
        if (fNoteTx) {
            if (tx.nNoteOp == NOTE_OP_MINT) {
                NoteMint m;
                if (DecodeNotePayload(tx.vchNotePayload, m)) { nNoteHouse = m.nHouseID; vNoteUnits = m.vUnits; }
            } else if (tx.nNoteOp == NOTE_OP_TRANSFER) {
                NoteTransfer x;
                if (DecodeNotePayload(tx.vchNotePayload, x)) { nNoteHouse = x.nHouseID; vNoteUnits = x.vUnits; nNoteDemandHeight = x.nDemandHeight; }
            } else if (tx.nNoteOp == NOTE_OP_DEMAND) {
                NoteDemand d;
                if (DecodeNotePayload(tx.vchNotePayload, d)) { nNoteHouse = d.nHouseID; vNoteUnits = d.vUnits; nNoteDemandHeight = (uint32_t)nHeight; }
            } else if (tx.nNoteOp == NOTE_OP_REDEEM) {
                // The dynamic-brassage spread (3.5) is an escrow output at
                // vout[1] - payload-driven like every other note tag, so
                // connect == rollforward.
                NoteRedeem r;
                if (DecodeNotePayload(tx.vchNotePayload, r) && r.fBrassage) {
                    fClaimEscrowChange = true;
                    nClaimHouse = r.nHouseID;
                }
            } else if (tx.nNoteOp == NOTE_OP_CLAIM) {
                // An insolvency claim may return escrow change at vout[1]; the
                // payload is self-contained (connect == rollforward), and the
                // contextual check pinned vout[1]'s script to the canonical
                // escrow script before this coin can exist.
                NoteClaim c;
                if (DecodeNotePayload(tx.vchNotePayload, c) && c.fEscrowChange) {
                    fClaimEscrowChange = true;
                    nClaimHouse = c.nHouseID;
                }
            }
        }

        // Term-deposit receipts (Phase 3.8) self-tag from the payload, exactly
        // like notes - no threaded dense id, so connect == rollforward. ORIGINATE
        // stamps origination = THIS block's height across the whole batch;
        // TRANSFER carries the payload's origination (== the spent receipt's,
        // enforced by tx_verify) so the receipt keeps its birth height and clock.
        bool fDepositTx = tx.nVersion == TRANSACTION_DEPOSIT_VERSION;
        uint32_t nDepHouse = 0;
        std::vector<uint64_t> vDepPrincipal;
        std::vector<uint32_t> vDepRate, vDepMaturity;
        uint32_t nDepOrigination = 0;
        bool fDepEscrowChange = false;
        uint32_t nDepEscrowHouse = 0;
        if (fDepositTx) {
            if (tx.nDepositOp == DEPOSIT_OP_ORIGINATE) {
                DepositOriginate o;
                if (DecodeDepositPayload(tx.vchDepositPayload, o)) {
                    nDepHouse = o.nHouseID; vDepPrincipal = o.vPrincipal;
                    vDepRate = o.vRateBps; vDepMaturity = o.vMaturityHeight;
                    nDepOrigination = (uint32_t)nHeight;
                }
            } else if (tx.nDepositOp == DEPOSIT_OP_TRANSFER) {
                DepositTransfer x;
                if (DecodeDepositPayload(tx.vchDepositPayload, x)) {
                    nDepHouse = x.nHouseID;
                    vDepPrincipal.push_back(x.nPrincipal);
                    vDepRate.push_back(x.nRateBps);
                    vDepMaturity.push_back(x.nMaturityHeight);
                    nDepOrigination = x.nOriginationHeight;
                }
            } else if (tx.nDepositOp == DEPOSIT_OP_CLAIM) {
                DepositClaim c;
                if (DecodeDepositPayload(tx.vchDepositPayload, c) && c.fEscrowChange) {
                    fDepEscrowChange = true;
                    nDepEscrowHouse = c.nHouseID;
                }
            }
        }

        for (size_t i = 0; i < tx.vout.size(); ++i) {
            bool fAsset = fNewAsset && i < 2;
            bool fControl = fNewAsset && i == 0;
            uint32_t nID = nNewAssetID ? nNewAssetID : nAssetID;
            bool overwrite = check ? cache.HaveCoin(COutPoint(txid, i)) : fCoinbase;
            Coin coin(tx.vout[i], nHeight, fCoinbase, fAsset, fControl, fAsset ? nID : 0);

            if (fBillTx) {
                if (tx.nBillOp == BILL_OP_ISSUE && i < 2)
                    coin.SetBill(i == 1 /* fEscrow */, nBillID);
                else if (tx.nBillOp == BILL_OP_ENDORSE && i == 0)
                    coin.SetBill(false, nBillID);
            }

            if (fHouseTx) {
                if (tx.nHouseOp == HOUSE_OP_REGISTER && i < nHousePledges)
                    coin.SetHouseEscrow(nHouseID);
                else if ((tx.nHouseOp == HOUSE_OP_TOPUP || tx.nHouseOp == HOUSE_OP_ADMIT) && i == 0)
                    coin.SetHouseEscrow(nHouseID);
                // The till locked at DEFER (3.5 D11) is escrow custody too.
                else if (tx.nHouseOp == HOUSE_OP_DEFER && i == 0)
                    coin.SetHouseEscrow(nHouseID);
            }

            if (fNoteTx && nNoteHouse != 0 && i < vNoteUnits.size())
                coin.SetNote(nNoteHouse, vNoteUnits[i], nNoteDemandHeight);

            if (fNoteTx && fClaimEscrowChange && i == 1)
                coin.SetHouseEscrow(nClaimHouse);

            if (fDepositTx && nDepHouse != 0 && i < vDepPrincipal.size())
                coin.SetDeposit(nDepHouse, vDepPrincipal[i], vDepRate[i], vDepMaturity[i], nDepOrigination);

            if (fDepositTx && fDepEscrowChange && i == 1)
                coin.SetHouseEscrow(nDepEscrowHouse);

            // Pool outputs (Phase 3.7) self-tag from the payload via the single
            // shared tagger - connect == rollforward == mempool by construction.
            ApplyPoolCoinTags(tx, i, coin);

            cache.AddCoin(COutPoint(txid, i), std::move(coin), overwrite);
        }
    }
}

bool CCoinsViewCache::SpendCoin(const COutPoint &outpoint, bool& fBitAsset, bool& fBitAssetControl, uint32_t& nAssetID, Coin* moveout) {
    CCoinsMap::iterator it = FetchCoin(outpoint);
    if (it == cacheCoins.end()) return false;
    fBitAsset = it->second.coin.fBitAsset;
    fBitAssetControl = it->second.coin.fBitAssetControl;
    nAssetID = it->second.coin.nAssetID;
    cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
    if (moveout) {
        *moveout = std::move(it->second.coin);
    }
    if (it->second.flags & CCoinsCacheEntry::FRESH) {
        cacheCoins.erase(it);
    } else {
        it->second.flags |= CCoinsCacheEntry::DIRTY;
        it->second.coin.Clear();
    }
    return true;
}

static const Coin coinEmpty;

const Coin& CCoinsViewCache::AccessCoin(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    if (it == cacheCoins.end()) {
        return coinEmpty;
    } else {
        return it->second.coin;
    }
}

bool CCoinsViewCache::HaveCoin(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    return (it != cacheCoins.end() && !it->second.coin.IsSpent());
}

bool CCoinsViewCache::HaveCoinInCache(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = cacheCoins.find(outpoint);
    return (it != cacheCoins.end() && !it->second.coin.IsSpent());
}

uint256 CCoinsViewCache::GetBestBlock() const {
    if (hashBlock.IsNull())
        hashBlock = base->GetBestBlock();
    return hashBlock;
}

void CCoinsViewCache::SetBestBlock(const uint256 &hashBlockIn) {
    hashBlock = hashBlockIn;
}

bool CCoinsViewCache::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlockIn) {
    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end(); it = mapCoins.erase(it)) {
        // Ignore non-dirty entries (optimization).
        if (!(it->second.flags & CCoinsCacheEntry::DIRTY)) {
            continue;
        }
        CCoinsMap::iterator itUs = cacheCoins.find(it->first);
        if (itUs == cacheCoins.end()) {
            // The parent cache does not have an entry, while the child does
            // We can ignore it if it's both FRESH and pruned in the child
            if (!(it->second.flags & CCoinsCacheEntry::FRESH && it->second.coin.IsSpent())) {
                // Otherwise we will need to create it in the parent
                // and move the data up and mark it as dirty
                CCoinsCacheEntry& entry = cacheCoins[it->first];
                entry.coin = std::move(it->second.coin);
                cachedCoinsUsage += entry.coin.DynamicMemoryUsage();
                entry.flags = CCoinsCacheEntry::DIRTY;
                // We can mark it FRESH in the parent if it was FRESH in the child
                // Otherwise it might have just been flushed from the parent's cache
                // and already exist in the grandparent
                if (it->second.flags & CCoinsCacheEntry::FRESH) {
                    entry.flags |= CCoinsCacheEntry::FRESH;
                }
            }
        } else {
            // Assert that the child cache entry was not marked FRESH if the
            // parent cache entry has unspent outputs. If this ever happens,
            // it means the FRESH flag was misapplied and there is a logic
            // error in the calling code.
            if ((it->second.flags & CCoinsCacheEntry::FRESH) && !itUs->second.coin.IsSpent()) {
                throw std::logic_error("FRESH flag misapplied to cache entry for base transaction with spendable outputs");
            }

            // Found the entry in the parent cache
            if ((itUs->second.flags & CCoinsCacheEntry::FRESH) && it->second.coin.IsSpent()) {
                // The grandparent does not have an entry, and the child is
                // modified and being pruned. This means we can just delete
                // it from the parent.
                cachedCoinsUsage -= itUs->second.coin.DynamicMemoryUsage();
                cacheCoins.erase(itUs);
            } else {
                // A normal modification.
                cachedCoinsUsage -= itUs->second.coin.DynamicMemoryUsage();
                itUs->second.coin = std::move(it->second.coin);
                cachedCoinsUsage += itUs->second.coin.DynamicMemoryUsage();
                itUs->second.flags |= CCoinsCacheEntry::DIRTY;
                // NOTE: It is possible the child has a FRESH flag here in
                // the event the entry we found in the parent is pruned. But
                // we must not copy that FRESH flag to the parent as that
                // pruned state likely still needs to be communicated to the
                // grandparent.
            }
        }
    }
    hashBlock = hashBlockIn;
    return true;
}

bool CCoinsViewCache::Flush() {
    bool fOk = base->BatchWrite(cacheCoins, hashBlock);
    cacheCoins.clear();
    cachedCoinsUsage = 0;
    return fOk;
}

void CCoinsViewCache::Uncache(const COutPoint& hash)
{
    CCoinsMap::iterator it = cacheCoins.find(hash);
    if (it != cacheCoins.end() && it->second.flags == 0) {
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
        cacheCoins.erase(it);
    }
}

unsigned int CCoinsViewCache::GetCacheSize() const {
    return cacheCoins.size();
}

CAmount CCoinsViewCache::GetValueIn(const CTransaction& tx) const
{
    if (tx.IsCoinBase())
        return 0;

    CAmount nResult = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        nResult += AccessCoin(tx.vin[i].prevout).out.nValue;

    return nResult;
}

bool CCoinsViewCache::HaveInputs(const CTransaction& tx) const
{
    if (!tx.IsCoinBase()) {
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            if (!HaveCoin(tx.vin[i].prevout)) {
                return false;
            }
        }
    }
    return true;
}

static const size_t MIN_TRANSACTION_OUTPUT_WEIGHT = WITNESS_SCALE_FACTOR * ::GetSerializeSize(CTxOut(), SER_NETWORK, PROTOCOL_VERSION);
static const size_t MAX_OUTPUTS_PER_BLOCK = MAX_BLOCK_WEIGHT / MIN_TRANSACTION_OUTPUT_WEIGHT;

const Coin& AccessByTxid(const CCoinsViewCache& view, const uint256& txid)
{
    COutPoint iter(txid, 0);
    while (iter.n < MAX_OUTPUTS_PER_BLOCK) {
        const Coin& alternate = view.AccessCoin(iter);
        if (!alternate.IsSpent()) return alternate;
        ++iter.n;
    }
    return coinEmpty;
}
