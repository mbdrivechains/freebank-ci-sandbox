// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation.h>

#include <arith_uint256.h>
#include <base58.h>
#include <bmmcache.h>
#include <chain.h>
#include <chainparams.h>
#include <checkpoints.h>
#include <checkqueue.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <cuckoocache.h>
#include <hash.h>
#include <init.h>
#include <net.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <policy/withdrawalbundle.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <reverse_iterator.h>
#include <script/script.h>
#include <script/sigcache.h>
#include <script/standard.h>
#include <bill.h>
#include <house.h>
#include <note.h>
#include <deposit.h>
#include <pool.h>
#include <sidechainclient.h>

#include <functional>
#include <timedata.h>
#include <tinyformat.h>
#include <txdb.h>
#include <txmempool.h>
#include <ui_interface.h>
#include <undo.h>
#include <util.h>
#include <utilmoneystr.h>
#include <utilstrencodings.h>
#include <validationinterface.h>
#include <warnings.h>

#include <future>
#include <sstream>

#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/thread.hpp>
#include <boost/bind/placeholders.hpp>

using namespace boost::placeholders;

#if defined(NDEBUG)
# error "Bitcoin cannot be compiled without assertions."
#endif

#define MICRO 0.000001
#define MILLI 0.001

/**
 * Global state
 */
namespace {
    struct CBlockIndexWorkComparator
    {
        bool operator()(const CBlockIndex *pa, const CBlockIndex *pb) const {
            // First by height
            if (pa->nHeight < pb->nHeight) return true;
            if (pa->nHeight > pb->nHeight) return false;

            // ... then by earliest time received, ...
            if (pa->nSequenceId < pb->nSequenceId) return false;
            if (pa->nSequenceId > pb->nSequenceId) return true;

            // Use pointer address as tie breaker (should only happen with blocks
            // loaded from disk, as those all have id 0).
            if (pa < pb) return false;
            if (pa > pb) return true;

            // Identical blocks.
            return false;
        }
    };
} // anon namespace

enum DisconnectResult
{
    DISCONNECT_OK,      // All good.
    DISCONNECT_UNCLEAN, // Rolled back, but UTXO set was inconsistent with block.
    DISCONNECT_FAILED   // Something else went wrong.
};

struct PerBlockConnectTrace {
    std::map<uint256, BitAssetTransactionData> mapAssetData;
    CBlockIndex* pindex = nullptr;
    std::shared_ptr<const CBlock> pblock;
    std::shared_ptr<std::vector<CTransactionRef>> conflictedTxs;
    PerBlockConnectTrace() : conflictedTxs(std::make_shared<std::vector<CTransactionRef>>()) {}
};
/**
 * Used to track blocks whose transactions were applied to the UTXO state as a
 * part of a single ActivateBestChainStep call.
 *
 * This class also tracks transactions that are removed from the mempool as
 * conflicts (per block) and can be used to pass all those transactions
 * through SyncTransaction.
 *
 * This class assumes (and asserts) that the conflicted transactions for a given
 * block are added via mempool callbacks prior to the BlockConnected() associated
 * with those transactions. If any transactions are marked conflicted, it is
 * assumed that an associated block will always be added.
 *
 * This class is single-use, once you call GetBlocksConnected() you have to throw
 * it away and make a new one.
 */
class ConnectTrace {
private:
    std::vector<PerBlockConnectTrace> blocksConnected;
    CTxMemPool &pool;

public:
    explicit ConnectTrace(CTxMemPool &_pool) : blocksConnected(1), pool(_pool) {
        pool.NotifyEntryRemoved.connect(boost::bind(&ConnectTrace::NotifyEntryRemoved, this, _1, _2));
    }

    ~ConnectTrace() {
        pool.NotifyEntryRemoved.disconnect(boost::bind(&ConnectTrace::NotifyEntryRemoved, this, _1, _2));
    }

    void BlockConnected(CBlockIndex* pindex, std::shared_ptr<const CBlock> pblock) {
        assert(!blocksConnected.back().pindex);
        assert(pindex);
        assert(pblock);
        blocksConnected.back().pindex = pindex;
        blocksConnected.back().pblock = std::move(pblock);
        blocksConnected.emplace_back();
    }

    std::vector<PerBlockConnectTrace>& GetBlocksConnected() {
        // We always keep one extra block at the end of our list because
        // blocks are added after all the conflicted transactions have
        // been filled in. Thus, the last entry should always be an empty
        // one waiting for the transactions from the next block. We pop
        // the last entry here to make sure the list we return is sane.
        assert(!blocksConnected.back().pindex);
        assert(blocksConnected.back().conflictedTxs->empty());
        blocksConnected.pop_back();
        return blocksConnected;
    }

    void NotifyEntryRemoved(CTransactionRef txRemoved, MemPoolRemovalReason reason) {
        assert(!blocksConnected.back().pindex);
        if (reason == MemPoolRemovalReason::CONFLICT) {
            blocksConnected.back().conflictedTxs->emplace_back(std::move(txRemoved));
        }
    }

    void SetBitAssetData(const uint256& txid, const BitAssetTransactionData& data) {
        blocksConnected.back().mapAssetData[txid] = data;
    }
};

/**
 * CChainState stores and provides an API to update our local knowledge of the
 * current best chain and header tree.
 *
 * It generally provides access to the current block tree, as well as functions
 * to provide new data, which it will appropriately validate and incorporate in
 * its state as necessary.
 *
 * Eventually, the API here is targeted at being exposed externally as a
 * consumable libconsensus library, so any functions added must only call
 * other class member functions, pure functions in other parts of the consensus
 * library, callbacks via the validation interface, or read/write-to-disk
 * functions (eventually this will also be via callbacks).
 */
class CChainState {
private:
    /**
     * The set of all CBlockIndex entries with BLOCK_VALID_TRANSACTIONS (for itself and all ancestors) and
     * as good as our current tip or better. Entries may be failed, though, and pruning nodes may be
     * missing the data for the block.
     */
    std::set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexCandidates;

    /**
     * Every received block is assigned a unique and increasing identifier, so we
     * know which one to give priority in case of a fork.
     */
    CCriticalSection cs_nBlockSequenceId;
    /** Blocks loaded from disk are assigned id 0, so start the counter at 1. */
    int32_t nBlockSequenceId = 1;
    /** Decreasing counter (used by subsequent preciousblock calls). */
    int32_t nBlockReverseSequenceId = -1;

    /** In order to efficiently track invalidity of headers, we keep the set of
      * blocks which we tried to connect and found to be invalid here (ie which
      * were set to BLOCK_FAILED_VALID since the last restart). We can then
      * walk this set and check if a new header is a descendant of something in
      * this set, preventing us from having to walk mapBlockIndex when we try
      * to connect a bad block and fail.
      *
      * While this is more complicated than marking everything which descends
      * from an invalid block as invalid at the time we discover it to be
      * invalid, doing so would require walking all of mapBlockIndex to find all
      * descendants. Since this case should be very rare, keeping track of all
      * BLOCK_FAILED_VALID blocks in a set should be just fine and work just as
      * well.
      *
      * Because we already walk mapBlockIndex in height-order at startup, we go
      * ahead and mark descendants of invalid blocks as FAILED_CHILD at that time,
      * instead of putting things in this set.
      */
    std::set<CBlockIndex*> g_failed_blocks;

public:
    CChain chainActive;
    BlockMap mapBlockIndex;
    std::map<uint256, CBlockIndex*> mapBlockMainHashIndex;
    std::multimap<CBlockIndex*, CBlockIndex*> mapBlocksUnlinked;
    CBlockIndex *pindexBestInvalid = nullptr;

    bool LoadBlockIndex(const Consensus::Params& consensus_params, CBlockTreeDB& blocktree);

    bool ActivateBestChain(CValidationState &state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock);

    bool AcceptBlockHeader(const CBlockHeader& block, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex);
    bool AcceptBlock(const std::shared_ptr<const CBlock>& pblock, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex, bool fRequested, const CDiskBlockPos* dbp, bool* fNewBlock);

    // Block (dis)connection on a given view:
    DisconnectResult DisconnectBlock(const CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view, bool fSideDB = true);
    bool ConnectBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex,
                    CCoinsViewCache& view, const CChainParams& chainparams, bool fJustCheck = false, bool fCheckBMM = true, ConnectTrace* connectTrace = nullptr);

    // Block disconnection on our pcoinsTip:
    bool DisconnectTip(CValidationState& state, const CChainParams& chainparams, DisconnectedBlockTransactions *disconnectpool);

    // Manual block validity manipulation:
    bool PreciousBlock(CValidationState& state, const CChainParams& params, CBlockIndex *pindex);
    bool InvalidateBlock(CValidationState& state, const CChainParams& chainparams, CBlockIndex *pindex);
    bool ResetBlockFailureFlags(CBlockIndex *pindex);

    bool ReplayBlocks(const CChainParams& params, CCoinsView* view);
    bool RewindBlockIndex(const CChainParams& params);
    bool LoadGenesisBlock(const CChainParams& chainparams);

    void PruneBlockIndexCandidates();

    void UnloadBlockIndex();

private:
    bool ActivateBestChainStep(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexMostWork, const std::shared_ptr<const CBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace);
    bool ConnectTip(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexNew, const std::shared_ptr<const CBlock>& pblock, ConnectTrace& connectTrace, DisconnectedBlockTransactions &disconnectpool);

    CBlockIndex* AddToBlockIndex(const CBlockHeader& block);
    /** Create a new block index entry for a given block hash */
    CBlockIndex * InsertBlockIndex(const uint256& hash, const uint256& hashMainBlock);
    void CheckBlockIndex(const Consensus::Params& consensusParams);

    void InvalidBlockFound(CBlockIndex *pindex, const CValidationState &state);
    CBlockIndex* FindMostWorkChain();
    bool ReceivedBlockTransactions(const CBlock &block, CValidationState& state, CBlockIndex *pindexNew, const CDiskBlockPos& pos, const Consensus::Params& consensusParams);


    bool RollforwardBlock(const CBlockIndex* pindex, CCoinsViewCache& inputs, const CChainParams& params);
} g_chainstate;

CCriticalSection cs_main;

BMMCache bmmCache;

BlockMap& mapBlockIndex = g_chainstate.mapBlockIndex;
std::map<uint256, CBlockIndex*>& mapBlockMainHashIndex = g_chainstate.mapBlockMainHashIndex;
CChain& chainActive = g_chainstate.chainActive;
CBlockIndex *pindexBestHeader = nullptr;
CWaitableCriticalSection csBestBlock;
CConditionVariable cvBlockChange;
int nScriptCheckThreads = 0;
std::atomic_bool fImporting(false);
std::atomic_bool fReindex(false);
bool fTxIndex = false;
bool fHavePruned = false;
bool fPruneMode = false;
bool fIsBareMultisigStd = DEFAULT_PERMIT_BAREMULTISIG;
bool fRequireStandard = true;
bool fCheckBlockIndex = false;
bool fCheckpointsEnabled = DEFAULT_CHECKPOINTS_ENABLED;
size_t nCoinCacheUsage = 5000 * 300;
uint64_t nPruneTarget = 0;
int64_t nMaxTipAge = DEFAULT_MAX_TIP_AGE;
bool fEnableReplacement = DEFAULT_ENABLE_REPLACEMENT;
bool fSidechainIndex = true;

uint256 hashAssumeValid;

CFeeRate minRelayTxFee = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE);
CAmount maxTxFee = DEFAULT_TRANSACTION_MAXFEE;

CBlockPolicyEstimator feeEstimator;
CTxMemPool mempool(&feeEstimator);

/** Constant stuff for coinbase transactions we create: */
CScript COINBASE_FLAGS;

const std::string strMessageMagic = "Bitcoin Signed Message:\n";
const std::string strRefundMessageMagic = "REFUND DhjM9iNapSA 3e243e21\n";

std::mutex mainBlockCacheMutex;
std::mutex mainBlockCacheReorgMutex;

// Internal stuff
namespace {
    CBlockIndex *&pindexBestInvalid = g_chainstate.pindexBestInvalid;

    /** All pairs A->B, where A (or one of its ancestors) misses transactions, but B has transactions.
     * Pruned nodes may have entries where B is missing data.
     */
    std::multimap<CBlockIndex*, CBlockIndex*>& mapBlocksUnlinked = g_chainstate.mapBlocksUnlinked;

    CCriticalSection cs_LastBlockFile;
    std::vector<CBlockFileInfo> vinfoBlockFile;
    int nLastBlockFile = 0;
    /** Global flag to indicate we should check to see if there are
     *  block/undo files that should be deleted.  Set on startup
     *  or if we allocate more file space when we're in prune mode
     */
    bool fCheckForPruning = false;

    /** Dirty block index entries. */
    std::set<CBlockIndex*> setDirtyBlockIndex;

    /** Dirty block file entries. */
    std::set<int> setDirtyFileInfo;
} // anon namespace

CBlockIndex* FindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator)
{
    // Find the first block the caller has in the main chain
    for (const uint256& hash : locator.vHave) {
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end())
        {
            CBlockIndex* pindex = (*mi).second;
            if (chain.Contains(pindex))
                return pindex;
            if (pindex->GetAncestor(chain.Height()) == chain.Tip()) {
                return chain.Tip();
            }
        }
    }
    return chain.Genesis();
}

std::unique_ptr<CCoinsViewDB> pcoinsdbview;
std::unique_ptr<CCoinsViewCache> pcoinsTip;
std::unique_ptr<CBlockTreeDB> pblocktree;
std::unique_ptr<CSidechainTreeDB> psidechaintree;
std::unique_ptr<BitAssetDB> passettree;
std::unique_ptr<BillDB> pbilltree;
std::unique_ptr<HouseDB> phousetree;
std::unique_ptr<PoolDB> ppooltree;

bool CheckHouseOperation(const CTransaction& tx, CValidationState& state, int nHeight,
                         const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                         const std::function<bool(const uint256&)>& fnHaveHouseHash,
                         const std::function<bool(const std::string&)>& fnHaveClassID,
                         const std::function<bool(const COutPoint&, Coin&)>& fnGetProofCoin,
                         const std::function<bool(uint32_t, uint256&)>& fnGetBlockHash,
                         CHouse& houseOut);

bool CheckNoteOperation(const CTransaction& tx, CValidationState& state, int nHeight, uint64_t nNoteUnitsIn,
                        const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                        const std::function<bool(const COutPoint&, Coin&)>& fnGetCoin,
                        const std::function<bool(const COutPoint&, Coin&)>& fnGetProofCoin,
                        const std::function<bool(uint32_t, uint256&)>& fnGetBlockHash,
                        CHouse& houseOut, bool& fHouseChanged);
bool CheckDepositOperation(const CTransaction& tx, CValidationState& state, int nHeight,
                           const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                           const std::function<bool(const COutPoint&, Coin&)>& fnGetCoin,
                           CHouse& houseOut, bool& fHouseChanged);
bool CheckPoolOperation(const CTransaction& tx, CValidationState& state, int nHeight,
                        const std::function<bool(uint32_t, CPool&)>& fnGetPool,
                        const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                        CPool& poolOut, CHouse& houseOut, bool& fHouseChanged, bool& fPoolRetired);

/** Verify a reserve proof set (declared outpoints + per-coin recency signatures)
 * against the live UTXO state, summing the proven liquid value into amountOut.
 * This is the "prove you own N liquid base-coin sats as of nAsOfHeight" primitive
 * shared by HOUSE_OP_ATTEST (the health report) and, since R-i7, NOTE_OP_MINT
 * (the rho-at-mint LIVENESS gate that closes DR-1 - a mint proves its reserves
 * are still unspent AT MINT TIME rather than trusting a stored snapshot the house
 * may have spent out from under). The caller owns the freshness bounds on
 * nAsOfHeight (ATTEST is monotone; MINT is staleness-only) and what it does with
 * the sum; this verifies the coins themselves. `prefix` namespaces the reject
 * reasons (ATTEST keeps its historical "bad-house-attest-*" strings verbatim). */
static bool VerifyReserveProofs(const uint256& houseID, uint32_t nAsOfHeight,
    const std::vector<AttestProof>& vProofs, const std::vector<CTxIn>& vin, int nHeight,
    const std::function<bool(const COutPoint&, Coin&)>& fnGetProofCoin,
    const std::function<bool(uint32_t, uint256&)>& fnGetBlockHash,
    CAmount& amountOut, CValidationState& state, const std::string& prefix)
{
    // The proving tx must not consume the reserves it proves.
    std::set<COutPoint> setProof;
    for (const AttestProof& p : vProofs)
        setProof.insert(p.outpoint);
    for (const CTxIn& in : vin) {
        if (setProof.count(in.prevout))
            return state.DoS(100, false, REJECT_INVALID, prefix + "-spends-reserve");
    }

    uint256 hashAsOf;
    if (!fnGetBlockHash(nAsOfHeight, hashAsOf))
        return state.DoS(10, false, REJECT_INVALID, prefix + "-asof-unknown");

    CAmount amountSum = 0;
    for (const AttestProof& p : vProofs) {
        Coin coin;
        if (!fnGetProofCoin(p.outpoint, coin) || coin.IsSpent())
            return state.DoS(10, false, REJECT_INVALID, prefix + "-coin-missing");
        // Owned as of nAsOfHeight: the coin must have existed then...
        if (coin.nHeight > nAsOfHeight)
            return state.DoS(100, false, REJECT_INVALID, prefix + "-coin-fresh");
        // ...be spendable NOW (coinbase maturity)...
        if (coin.IsCoinBase() && nHeight - (int)coin.nHeight < COINBASE_MATURITY)
            return state.DoS(100, false, REJECT_INVALID, prefix + "-coin-immature");
        // ...and be PLAIN liquid value: consensus-tagged coins (escrow, bills,
        // notes, deposit receipts, LP shares, pool custody, assets) are either
        // already counted in the cap math or not base value at all. The P2PKH
        // script check below incidentally blocks the OP_DROP-OP_TRUE escrow
        // coins, but a P2PKH LP-share / deposit-receipt dust coin would slip
        // through and inflate the proven liquid till - so reject every tag
        // here rather than rely on the script coincidence (3.7 review).
        if (coin.fBitAsset || coin.fBitAssetControl || coin.fBill ||
                coin.fBillEscrow || coin.fHouseEscrow || coin.fNote ||
                coin.fDeposit || coin.fPoolEscrow || coin.fLpShare)
            return state.DoS(100, false, REJECT_INVALID, prefix + "-coin-tagged");

        // v1 script restriction: single-key P2PKH / P2WPKH matching the declared
        // key, which must sign the recency challenge.
        const CPubKey pub(p.vchPubKey);
        const CKeyID keyid = pub.GetID();
        if (coin.out.scriptPubKey != GetScriptForDestination(keyid) &&
                coin.out.scriptPubKey != GetScriptForDestination(WitnessV0KeyHash(keyid)))
            return state.DoS(100, false, REJECT_INVALID, prefix + "-coin-script");

        const uint256 challenge = HouseAttestChallenge(houseID, nAsOfHeight, hashAsOf, p.outpoint);
        if (!pub.Verify(challenge, p.vchSig))
            return state.DoS(100, false, REJECT_INVALID, prefix + "-proof-sig");

        amountSum += coin.out.nValue;
    }
    amountOut = amountSum;
    return true;
}

/** The live escrow pot of a house: the sum of every still-unspent pledge
 * outpoint's value (fnGetCoin resolves against the caller's view). The CHouse
 * record's amountPledge fields deliberately survive coin reclaims (the 3.1
 * undo design), so record sums would OVERSTATE the pot - the waterfall
 * snapshot must count actual lockable coins. */
/** Every outpoint that could hold this house's escrow: the partner pledge
 * lists plus the escrow-change outpoints created by waterfall claims. */
static std::vector<COutPoint> HouseEscrowOutpoints(const CHouse& house)
{
    std::vector<COutPoint> vOut;
    for (const HousePartner& p : house.vPartner)
        vOut.insert(vOut.end(), p.vOutPledge.begin(), p.vOutPledge.end());
    vOut.insert(vOut.end(), house.vOutEscrowChange.begin(), house.vOutEscrowChange.end());
    // The TILL locked at DEFER (3.5 D11) is part of the pot: that is the whole
    // point - a suspended house's reserves must be reachable by the holders it
    // has stopped paying. It collapses the run-payoff cliff from 1/lambda
    // toward 1/lambda + rho.
    vOut.insert(vOut.end(), house.vOutReserveLock.begin(), house.vOutReserveLock.end());
    return vOut;
}

static CAmount HouseLiveEscrowPot(const CHouse& house,
                                  const std::function<bool(const COutPoint&, Coin&)>& fnGetCoin)
{
    CAmount pot = 0;
    for (const COutPoint& out : HouseEscrowOutpoints(house)) {
        Coin coin;
        if (fnGetCoin(out, coin) && !coin.IsSpent() &&
                coin.fHouseEscrow && coin.nHouseID == house.nHouseID)
            pot += coin.out.nValue;
    }
    return pot;
}

/** Materialize insolvency on the house record (called by the FIRST waterfall
 * op - a note CLAIM, or a residual settle for a zero-liability house). The
 * pot/units snapshot fixes the pro-rata denominator forever (D5); the height
 * stamp drives the DisconnectBlock stamp-match undo. */
static void MaterializeInsolvency(CHouse& house, int nHeight,
                                  const std::function<bool(const COutPoint&, Coin&)>& fnGetCoin)
{
    house.status = HOUSE_STATUS_INSOLVENT;
    house.nInsolventHeight = (uint32_t)nHeight;
    house.nInsolventUnits = house.nMintedUnits;
    house.amountInsolventPot = HouseLiveEscrowPot(house, fnGetCoin);
    // Freeze the JUNIOR deposit tranche denominator (Phase 3.8). The deposit pot
    // is DERIVED at claim time as max(0, pot - nInsolventUnits) - the residual the
    // note par-cap leaves - so deposits are strictly junior to notes and provably
    // cannot touch the senior note par tranche, and partners are junior to both.
    house.nInsolventDepositPrincipal = house.nDepositUnits;

    // Freeze each partner's LIVE escrow contribution as their residual weight
    // (3.4 review): a partner who legitimately reclaimed (tail expired, cap
    // consistent) has an empty vOutPledge and therefore weighs zero - their
    // capital is not in the pot, so they take no residual from it. The first
    // waterfall op runs before any claim change exists, so the per-partner
    // sum here equals amountInsolventPot exactly.
    for (HousePartner& p : house.vPartner) {
        CAmount amountLive = 0;
        for (const COutPoint& out : p.vOutPledge) {
            Coin coin;
            if (fnGetCoin(out, coin) && !coin.IsSpent() &&
                    coin.fHouseEscrow && coin.nHouseID == house.nHouseID)
                amountLive += coin.out.nValue;
        }
        p.amountInsolventPledge = amountLive;
    }
}

bool CheckBillOperation(const CTransaction& tx, CValidationState& state, int nHeight, const CAmount& nTxFee,
                        const std::function<bool(uint32_t, CBill&)>& fnGetBill,
                        const std::function<bool(const uint256&)>& fnHaveBillHash,
                        CBill& billOut);

enum FlushStateMode {
    FLUSH_STATE_NONE,
    FLUSH_STATE_IF_NEEDED,
    FLUSH_STATE_PERIODIC,
    FLUSH_STATE_ALWAYS
};

// See definition for documentation
static bool FlushStateToDisk(const CChainParams& chainParams, CValidationState &state, FlushStateMode mode, int nManualPruneHeight=0);
static void FindFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight);
static void FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight);
bool CheckInputs(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks = nullptr);
static FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly = false);

bool CheckFinalTx(const CTransaction &tx, int flags)
{
    AssertLockHeld(cs_main);

    // By convention a negative value for flags indicates that the
    // current network-enforced consensus rules should be used. In
    // a future soft-fork scenario that would mean checking which
    // rules would be enforced for the next block and setting the
    // appropriate flags. At the present time no soft-forks are
    // scheduled, so no flags are set.
    flags = std::max(flags, 0);

    // CheckFinalTx() uses chainActive.Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // CBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // IsFinalTx() with one more than chainActive.Height().
    const int nBlockHeight = chainActive.Height() + 1;

    // BIP113 requires that time-locked transactions have nLockTime set to
    // less than the median time of the previous block they're contained in.
    // When the next block is created its previous block will be the current
    // chain tip, so we use that to calculate the median time passed to
    // IsFinalTx() if LOCKTIME_MEDIAN_TIME_PAST is set.
    const int64_t nBlockTime = (flags & LOCKTIME_MEDIAN_TIME_PAST)
                             ? chainActive.Tip()->GetMedianTimePast()
                             : GetAdjustedTime();

    return IsFinalTx(tx, nBlockHeight, nBlockTime);
}

bool TestLockPointValidity(const LockPoints* lp)
{
    AssertLockHeld(cs_main);
    assert(lp);
    // If there are relative lock times then the maxInputBlock will be set
    // If there are no relative lock times, the LockPoints don't depend on the chain
    if (lp->maxInputBlock) {
        // Check whether chainActive is an extension of the block at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        if (!chainActive.Contains(lp->maxInputBlock)) {
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

bool CheckSequenceLocks(const CTransaction &tx, int flags, LockPoints* lp, bool useExistingLockPoints)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(mempool.cs);

    CBlockIndex* tip = chainActive.Tip();
    assert(tip != nullptr);

    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocks() uses chainActive.Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than chainActive.Height()
    index.nHeight = tip->nHeight + 1;

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints) {
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    }
    else {
        // pcoinsTip contains the UTXO set for chainActive.Tip()
        CCoinsViewMemPool viewMemPool(pcoinsTip.get(), mempool);
        std::vector<int> prevheights;
        prevheights.resize(tx.vin.size());
        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
            const CTxIn& txin = tx.vin[txinIndex];
            Coin coin;
            if (!viewMemPool.GetCoin(txin.prevout, coin)) {
                return error("%s: Missing input", __func__);
            }
            if (coin.nHeight == MEMPOOL_HEIGHT) {
                // Assume all mempool transaction confirm in the next block
                prevheights[txinIndex] = tip->nHeight + 1;
            } else {
                prevheights[txinIndex] = coin.nHeight;
            }
        }
        lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
        if (lp) {
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the block with the highest height of
            // all the blocks which have sequence locked prevouts.
            // This hash needs to still be on the chain
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBlock
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock. Since we assume
            // input height of tip+1 for mempool txs and test the resulting
            // lockPair from CalculateSequenceLocks against tip+1.  We know
            // EvaluateSequenceLocks will fail if there was a non-zero sequence
            // lock on a mempool input, so we can use the return value of
            // CheckSequenceLocks to indicate the LockPoints validity
            int maxInputHeight = 0;
            for (int height : prevheights) {
                // Can ignore mempool inputs since we'll fail if they had non-zero locks
                if (height != tip->nHeight+1) {
                    maxInputHeight = std::max(maxInputHeight, height);
                }
            }
            lp->maxInputBlock = tip->GetAncestor(maxInputHeight);
        }
    }
    return EvaluateSequenceLocks(index, lockPair);
}

// Returns the script flags which should be checked for a given block
static unsigned int GetBlockScriptFlags(const CBlockIndex* pindex, const Consensus::Params& chainparams);

static void LimitMempoolSize(CTxMemPool& pool, size_t limit, unsigned long age) {
    int expired = pool.Expire(GetTime() - age);
    if (expired != 0) {
        LogPrint(BCLog::MEMPOOL, "Expired %i transactions from the memory pool\n", expired);
    }

    std::vector<COutPoint> vNoSpendsRemaining;
    pool.TrimToSize(limit, &vNoSpendsRemaining);
    for (const COutPoint& removed : vNoSpendsRemaining)
        pcoinsTip->Uncache(removed);
}

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState &state)
{
    return strprintf("%s%s (code %i)",
        state.GetRejectReason(),
        state.GetDebugMessage().empty() ? "" : ", "+state.GetDebugMessage(),
        state.GetRejectCode());
}

static bool IsCurrentForFeeEstimation()
{
    AssertLockHeld(cs_main);
    if (IsInitialBlockDownload())
        return false;
    if (chainActive.Tip()->GetBlockTime() < (GetTime() - MAX_FEE_ESTIMATION_TIP_AGE))
        return false;
    if (chainActive.Height() < pindexBestHeader->nHeight - 1)
        return false;
    return true;
}

/* Make mempool consistent after a reorg, by re-adding or recursively erasing
 * disconnected block transactions from the mempool, and also removing any
 * other transactions from the mempool that are no longer valid given the new
 * tip/height.
 *
 * Note: we assume that disconnectpool only contains transactions that are NOT
 * confirmed in the current chain nor already in the mempool (otherwise,
 * in-mempool descendants of such transactions would be removed).
 *
 * Passing fAddToMempool=false will skip trying to add the transactions back,
 * and instead just erase from the mempool as needed.
 */

/** Evict mempool house (v12) / note (v13) operations that chain events have
 * made consensus-invalid.
 *
 * These ops are the one family whose validity does NOT reduce to their inputs:
 * the 3.4 status machine is DERIVED (HouseEffectiveStatus), so a pending MINT
 * dies the moment the chain crosses its house's attestation deadline - no coin
 * is spent, and the mempool's conflict tracking is blind to it. The same holds
 * for an ATTEST whose approver is tailed by a confirmed EXIT, an op whose
 * house was wound down, an attestation whose proof coin got spent or whose
 * as-of block was reorged away, a REGISTER whose class-id was taken, and so
 * on. CreateNewBlock throws on TestBlockValidity failure, so ONE such tx
 * bricks BMM template creation - and a bricked template means no block, so
 * nothing would ever heal it (the pool would clear only at -mempoolexpiry,
 * ~14 days).
 *
 * The 3.4 review's lesson: do NOT enumerate staleness causes (the first cut
 * did, and missed the whole lazy-transition class plus approver-set changes).
 * Re-run the REAL contextual checks against the current tip and evict on any
 * failure. Node policy only - consensus is untouched. Cost is bounded: only
 * v12/v13 txs do work, and the one-op-per-house guard caps them at one per
 * house. */
static void EvictStaleHouseNoteOps()
{
    AssertLockHeld(cs_main);

    std::vector<std::pair<CTransactionRef, std::string>> vEvict;
    {
        LOCK(mempool.cs);
        const int nNextHeight = chainActive.Height() + 1;
        CCoinsViewMemPool viewMempool(pcoinsTip.get(), mempool);

        auto fnGetHouse = [](uint32_t nID, CHouse& house) { return phousetree->GetHouse(nID, house); };
        auto fnHaveHouseHash = [](const uint256& hash) { return phousetree->HaveHouseHash(hash); };
        auto fnHaveClassID = [](const std::string& strClassID) { return phousetree->HaveClassID(strClassID); };
        // Attestation proofs and escrow read CONFIRMED state (parent-state
        // semantics: a mempool spend of a reserve coin does not invalidate an
        // attestation - both can ride the same block).
        auto fnGetProofCoin = [](const COutPoint& out, Coin& coin) {
            return pcoinsTip->GetCoin(out, coin) && !coin.IsSpent();
        };
        auto fnGetBlockHash = [](uint32_t nH, uint256& hash) {
            if ((int64_t)nH > (int64_t)chainActive.Height())
                return false;
            const CBlockIndex* p = chainActive[(int)nH];
            if (!p)
                return false;
            hash = p->GetBlockHash();
            return true;
        };
        // Note units may come from an unconfirmed parent (transfers chain in
        // the mempool), so unit accounting uses the mempool view.
        auto fnGetCoin = [&](const COutPoint& out, Coin& coin) {
            return viewMempool.GetCoin(out, coin) && !coin.IsSpent();
        };

        auto fnGetPool = [](uint32_t nID, CPool& pool) { return ppooltree->GetPool(nID, pool); };

        for (CTxMemPool::txiter mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); mi++) {
            const CTransaction& mtx = mi->GetTx();
            const bool fHouseTx = (mtx.nVersion == TRANSACTION_HOUSE_VERSION);
            const bool fNoteTx = (mtx.nVersion == TRANSACTION_NOTE_VERSION);
            const bool fDepositTx = (mtx.nVersion == TRANSACTION_DEPOSIT_VERSION);
            const bool fPoolTx = (mtx.nVersion == TRANSACTION_POOL_VERSION);
            if (!fHouseTx && !fNoteTx && !fDepositTx && !fPoolTx)
                continue;

            CValidationState stateStale;
            bool fStale = false;

            if (fHouseTx) {
                CHouse houseResult;
                if (!CheckHouseOperation(mtx, stateStale, nNextHeight, fnGetHouse, fnHaveHouseHash,
                        fnHaveClassID, fnGetProofCoin, fnGetBlockHash, houseResult))
                    fStale = true;
            } else if (fNoteTx) {
                uint64_t nNoteUnitsIn = 0;
                for (const CTxIn& in : mtx.vin) {
                    Coin coin;
                    if (fnGetCoin(in.prevout, coin) && coin.fNote)
                        nNoteUnitsIn += coin.nNoteUnits;
                }
                CHouse houseResult;
                bool fHouseChanged = false;
                if (!CheckNoteOperation(mtx, stateStale, nNextHeight, nNoteUnitsIn, fnGetHouse,
                        fnGetCoin, fnGetProofCoin, fnGetBlockHash, houseResult, fHouseChanged))
                    fStale = true;
            } else if (fDepositTx) {
                CHouse houseResult;
                bool fHouseChanged = false;
                if (!CheckDepositOperation(mtx, stateStale, nNextHeight, fnGetHouse, fnGetCoin, houseResult, fHouseChanged))
                    fStale = true;
            } else { // fPoolTx: a connected pool op moved the priors every
                     // pooled loser bound; a governance op can close the house
                     // a pending CREATE needs Open. Re-run the real check.
                CPool poolResult;
                CHouse houseResult;
                bool fHouseChanged = false, fPoolRetired = false;
                if (!CheckPoolOperation(mtx, stateStale, nNextHeight, fnGetPool, fnGetHouse,
                        poolResult, houseResult, fHouseChanged, fPoolRetired))
                    fStale = true;
            }

            if (fStale)
                vEvict.push_back(std::make_pair(mi->GetSharedTx(), stateStale.GetRejectReason()));
        }
    }
    for (const std::pair<CTransactionRef, std::string>& e : vEvict) {
        // Log the REASON: an eviction here means the pool held a tx that would
        // have bricked the next template, and "why" is the only thing that
        // distinguishes an expected staleness from a consensus bug.
        LogPrintf("%s: evicting now-invalid house/note op %s from mempool (%s)\n",
                  __func__, e.first->GetHash().ToString(), e.second);
        mempool.removeRecursive(*e.first, MemPoolRemovalReason::CONFLICT);
    }
}

void UpdateMempoolForReorg(DisconnectedBlockTransactions &disconnectpool, bool fAddToMempool)
{
    AssertLockHeld(cs_main);
    std::vector<uint256> vHashUpdate;
    // disconnectpool's insertion_order index sorts the entries from
    // oldest to newest, but the oldest entry will be the last tx from the
    // latest mined block that was disconnected.
    // Iterate disconnectpool in reverse, so that we add transactions
    // back to the mempool starting with the earliest transaction that had
    // been previously seen in a block.
    auto it = disconnectpool.queuedTx.get<insertion_order>().rbegin();
    while (it != disconnectpool.queuedTx.get<insertion_order>().rend()) {
        // ignore validation errors in resurrected transactions
        CValidationState stateDummy;
        if (!fAddToMempool || (*it)->IsCoinBase() ||
            !AcceptToMemoryPool(mempool, stateDummy, *it, nullptr /* pfMissingInputs */,
                                nullptr /* plTxnReplaced */, true /* bypass_limits */, 0 /* nAbsurdFee */)) {
            // If the transaction doesn't make it in to the mempool, remove any
            // transactions that depend on it (which would now be orphans).
            mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
        } else if (mempool.exists((*it)->GetHash())) {
            vHashUpdate.push_back((*it)->GetHash());
        }
        ++it;
    }
    disconnectpool.queuedTx.clear();
    // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
    // no in-mempool children, which is generally not true when adding
    // previously-confirmed transactions back to the mempool.
    // UpdateTransactionsFromBlock finds descendants of any transactions in
    // the disconnectpool that were added back and cleans up the mempool state.
    mempool.UpdateTransactionsFromBlock(vHashUpdate);

    // We also need to remove any now-immature transactions
    mempool.removeForReorg(pcoinsTip.get(), chainActive.Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
    // House/note ops depend on chain state they do not spend (derived status,
    // approver sets, attestation priors) - re-validate against the post-reorg
    // branch and drop whatever no longer connects.
    EvictStaleHouseNoteOps();
    // Re-limit mempool size, in case we added any transactions
    LimitMempoolSize(mempool, gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
}

// Used to avoid mempool polluting consensus critical paths if CCoinsViewMempool
// were somehow broken and returning the wrong scriptPubKeys
static bool CheckInputsFromMempoolAndCache(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &view, CTxMemPool& pool,
                 unsigned int flags, bool cacheSigStore, PrecomputedTransactionData& txdata) {
    AssertLockHeld(cs_main);

    // pool.cs should be locked already, but go ahead and re-take the lock here
    // to enforce that mempool doesn't change between when we check the view
    // and when we actually call through to CheckInputs
    LOCK(pool.cs);

    assert(!tx.IsCoinBase());
    for (const CTxIn& txin : tx.vin) {
        const Coin& coin = view.AccessCoin(txin.prevout);

        // At this point we haven't actually checked if the coins are all
        // available (or shouldn't assume we have, since CheckInputs does).
        // So we just return failure if the inputs are not available here,
        // and then only have to check equivalence for available inputs.
        if (coin.IsSpent()) return false;

        const CTransactionRef& txFrom = pool.get(txin.prevout.hash);
        if (txFrom) {
            assert(txFrom->GetHash() == txin.prevout.hash);
            assert(txFrom->vout.size() > txin.prevout.n);
            assert(txFrom->vout[txin.prevout.n] == coin.out);
        } else {
            const Coin& coinFromDisk = pcoinsTip->AccessCoin(txin.prevout);
            assert(!coinFromDisk.IsSpent());
            assert(coinFromDisk.out == coin.out);
        }
    }

    return CheckInputs(tx, state, view, true, flags, cacheSigStore, true, txdata);
}

static bool AcceptToMemoryPoolWorker(const CChainParams& chainparams, CTxMemPool& pool, CValidationState& state, const CTransactionRef& ptx,
                              bool* pfMissingInputs, int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced,
                              bool bypass_limits, const CAmount& nAbsurdFee, std::vector<COutPoint>& coins_to_uncache)
{
    const CTransaction& tx = *ptx;
    const uint256 hash = tx.GetHash();
    AssertLockHeld(cs_main);
    LOCK(pool.cs); // mempool "read lock" (held through GetMainSignals().TransactionAddedToMempool())
    if (pfMissingInputs) {
        *pfMissingInputs = false;
    }

    if (!CheckTransaction(tx, state))
        return false; // state filled in by CheckTransaction

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "coinbase");

    // Reject transactions with witness before segregated witness activates (override with -prematurewitness)
    bool witnessEnabled = IsWitnessEnabled(chainActive.Tip(), chainparams.GetConsensus());
    if (!gArgs.GetBoolArg("-prematurewitness", false) && tx.HasWitness() && !witnessEnabled) {
        return state.DoS(0, false, REJECT_NONSTANDARD, "no-witness-yet", true);
    }

    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
    std::string reason;
    if (fRequireStandard && !IsStandardTx(tx, reason, witnessEnabled))
        return state.DoS(0, false, REJECT_NONSTANDARD, reason);

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!CheckFinalTx(tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
        return state.DoS(0, false, REJECT_NONSTANDARD, "non-final");

    // is it already in the memory pool?
    if (pool.exists(hash)) {
        return state.Invalid(false, REJECT_DUPLICATE, "txn-already-in-mempool");
    }

    // If this is a withdrawal check that it is valid
    for (const CTxOut& txout : tx.vout) {
        const CScript& scriptPubKey = txout.scriptPubKey;
        std::vector<unsigned char> vch;
        if (!scriptPubKey.IsSidechainObj(vch))
            continue;

        SidechainObj *obj = ParseSidechainObj(vch);
        if (!obj)
            return state.Invalid(false, REJECT_INVALID, "invalid-sidechain-obj-script");

        if (obj->sidechainop == DB_SIDECHAIN_WITHDRAWAL_OP) {
            SidechainWithdrawal *withdrawal = dynamic_cast<SidechainWithdrawal*>(obj);
            // Verify that burn output actually exists
            bool fBurnFound = false;
            for (const CTxOut& o : tx.vout) {
                if (o.scriptPubKey.size()
                        && o.scriptPubKey[0] == OP_RETURN
                        && o.nValue == withdrawal->amount)
                {
                    // Make sure that the burn amount & fee are valid
                    if (withdrawal->amount > 0 && withdrawal->mainchainFee > 0 && withdrawal->amount > withdrawal->mainchainFee)
                        fBurnFound = true;
                }
            }
            if (!fBurnFound) {
                return state.DoS(100, false, REJECT_INVALID, "invalid-withdrawal-missing-or-invalid-burn");
            }
        }
    }

    // If this transaction is a withdrawal refund request, verify it.
    for (const CTxOut& o : tx.vout) {
        const CScript& scriptPubKey = o.scriptPubKey;
        uint256 id;
        std::vector<unsigned char> vchSig;
        if (!scriptPubKey.IsWithdrawalRefundRequest(id, vchSig))
            continue;

        if (id.IsNull()) {
            return state.DoS(100, error("%s: Invalid withdrawal refund!", __func__),
                        REJECT_INVALID, "verify-withdrawal-refund-no-script");
        }

        // Check if a refund for this withdrawal is already in our memory pool
        if (pool.WithdrawalRefundExists(id)) {
            return state.DoS(100, error("%s: Invalid withdrawal refund!", __func__),
                        REJECT_INVALID, "refund-already-in-mempool");
        }

        SidechainWithdrawal withdrawal;
        if (!VerifyWithdrawalRefundRequest(id, vchSig, withdrawal)) {
            return state.DoS(100, error("%s: Invalid withdrawal refund!", __func__),
                        REJECT_INVALID, "verify-withdrawal-refund-invalid");
        }
    }

    // Check for conflicts with in-memory transactions
    std::set<uint256> setConflicts;
    for (const CTxIn &txin : tx.vin)
    {
        auto itConflicting = pool.mapNextTx.find(txin.prevout);
        if (itConflicting != pool.mapNextTx.end())
        {
            const CTransaction *ptxConflicting = itConflicting->second;
            if (!setConflicts.count(ptxConflicting->GetHash()))
            {
                // Allow opt-out of transaction replacement by setting
                // nSequence > MAX_BIP125_RBF_SEQUENCE (SEQUENCE_FINAL-2) on all inputs.
                //
                // SEQUENCE_FINAL-1 is picked to still allow use of nLockTime by
                // non-replaceable transactions. All inputs rather than just one
                // is for the sake of multi-party protocols, where we don't
                // want a single party to be able to disable replacement.
                //
                // The opt-out ignores descendants as anyone relying on
                // first-seen mempool behavior should be checking all
                // unconfirmed ancestors anyway; doing otherwise is hopelessly
                // insecure.
                bool fReplacementOptOut = true;
                if (fEnableReplacement)
                {
                    for (const CTxIn &_txin : ptxConflicting->vin)
                    {
                        if (_txin.nSequence <= MAX_BIP125_RBF_SEQUENCE)
                        {
                            fReplacementOptOut = false;
                            break;
                        }
                    }
                }
                if (fReplacementOptOut) {
                    return state.Invalid(false, REJECT_DUPLICATE, "txn-mempool-conflict");
                }

                setConflicts.insert(ptxConflicting->GetHash());
            }
        }
    }

    {
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);

        LockPoints lp;
        CCoinsViewMemPool viewMemPool(pcoinsTip.get(), pool);
        view.SetBackend(viewMemPool);

        // do all inputs exist?
        for (const CTxIn txin : tx.vin) {
            if (!pcoinsTip->HaveCoinInCache(txin.prevout)) {
                coins_to_uncache.push_back(txin.prevout);
            }
            if (!view.HaveCoin(txin.prevout)) {
                // Are inputs missing because we already have the tx?
                for (size_t out = 0; out < tx.vout.size(); out++) {
                    // Optimistically just do efficient check of cache for outputs
                    if (pcoinsTip->HaveCoinInCache(COutPoint(hash, out))) {
                        return state.Invalid(false, REJECT_DUPLICATE, "txn-already-known");
                    }
                }
                // Otherwise assume this might be an orphan tx for which we just haven't seen parents yet
                if (pfMissingInputs) {
                    *pfMissingInputs = true;
                }
                return false; // fMissingInputs and !state.IsInvalid() is used to detect this condition, don't set state.Invalid()
            }
        }

        // Bring the best block into scope
        view.GetBestBlock();

        // we have all inputs cached now, so switch back to dummy, so we don't need to keep lock on mempool
        view.SetBackend(dummy);

        // Only accept BIP68 sequence locked transactions that can be mined in the next
        // block; we don't want our mempool filled up with transactions that can't
        // be mined yet.
        // Must keep pool.cs for this unless we change CheckSequenceLocks to take a
        // CoinsViewCache instead of create its own
        if (!CheckSequenceLocks(tx, STANDARD_LOCKTIME_VERIFY_FLAGS, &lp))
            return state.DoS(0, false, REJECT_NONSTANDARD, "non-BIP68-final");

        CAmount nFees = 0;
        if (!Consensus::CheckTxInputs(tx, state, view, GetSpendHeight(view), nFees)) {
            return error("%s: Consensus::CheckTxInputs: %s, %s", __func__, tx.GetHash().ToString(), FormatStateMessage(state));
        }

        // Contextual bill checks - keeps invalid bill operations out of the
        // mempool so the BMM block assembler never templates them
        if (tx.nVersion == TRANSACTION_BILL_VERSION) {
            auto fnGetBill = [](uint32_t nID, CBill& bill) { return pbilltree->GetBill(nID, bill); };
            auto fnHaveBillHash = [](const uint256& hash) { return pbilltree->HaveBillHash(hash); };
            CBill billResult;
            if (!CheckBillOperation(tx, state, GetSpendHeight(view), nFees, fnGetBill, fnHaveBillHash, billResult))
                return error("%s: CheckBillOperation: %s, %s", __func__, tx.GetHash().ToString(), FormatStateMessage(state));
        }

        // Contextual house checks. Consensus allows ONE house op per house per
        // block (deterministic undo), and house ops other than RECLAIM spend no
        // house-tagged coins, so two ops for the same house could otherwise sit
        // in the mempool together and invalidate our own BMM template. Reject
        // at admission if the mempool already carries an op for this house.
        if (tx.nVersion == TRANSACTION_HOUSE_VERSION) {
            auto fnGetHouse = [](uint32_t nID, CHouse& house) { return phousetree->GetHouse(nID, house); };
            auto fnHaveHouseHash = [](const uint256& hash) { return phousetree->HaveHouseHash(hash); };
            auto fnHaveClassID = [](const std::string& strClassID) { return phousetree->HaveClassID(strClassID); };
            // ATTEST reserve proofs are checked against the CONFIRMED chain
            // state (pcoinsTip, parent-state semantics) - NOT the ATMP view,
            // whose backend is a dummy once inputs are cached, and NOT the
            // mempool, so a pending spend of a reserve coin cannot make the
            // attestation and the spend mutually exclusive in a template.
            auto fnGetProofCoin = [](const COutPoint& out, Coin& coin) {
                return pcoinsTip->GetCoin(out, coin) && !coin.IsSpent();
            };
            auto fnGetBlockHash = [](uint32_t nH, uint256& hash) {
                if ((int64_t)nH > (int64_t)chainActive.Height())
                    return false;
                const CBlockIndex* p = chainActive[(int)nH];
                if (!p)
                    return false;
                hash = p->GetBlockHash();
                return true;
            };
            CHouse houseResult;
            if (!CheckHouseOperation(tx, state, GetSpendHeight(view), fnGetHouse, fnHaveHouseHash, fnHaveClassID, fnGetProofCoin, fnGetBlockHash, houseResult))
                return error("%s: CheckHouseOperation: %s, %s", __func__, tx.GetHash().ToString(), FormatStateMessage(state));

            // A non-register incoming op targets an EXISTING house (dense id
            // from the DB); a mempool REGISTER's house is not in the DB yet, so
            // the two can never collide. Only decode mempool REGISTERs when the
            // incoming tx is ALSO a REGISTER (classID / houseID collision);
            // otherwise compare the leading 4-byte dense nHouseID directly. This
            // keeps the common (non-register) case decode-free.
            const bool fIncomingRegister = (tx.nHouseOp == HOUSE_OP_REGISTER);
            const uint256 hashNew = fIncomingRegister ? houseResult.houseID : uint256();
            std::string strClassNew;
            if (fIncomingRegister) {
                HouseRegister reg;
                if (DecodeHousePayload(tx.vchHousePayload, reg))
                    strClassNew = reg.strClassID;
            }
            uint32_t nHouseIDNewLE = 0;
            if (!fIncomingRegister && tx.vchHousePayload.size() >= 4)
                memcpy(&nHouseIDNewLE, tx.vchHousePayload.data(), 4);

            for (CTxMemPool::txiter mi = pool.mapTx.begin(); mi != pool.mapTx.end(); mi++) {
                const CTransaction& mtx = mi->GetTx();
                if (mtx.nVersion == TRANSACTION_HOUSE_VERSION) {
                    const bool fTheirsRegister = (mtx.nHouseOp == HOUSE_OP_REGISTER);
                    if (fIncomingRegister && fTheirsRegister) {
                        HouseRegister mreg;
                        if (DecodeHousePayload(mtx.vchHousePayload, mreg)) {
                            if (HouseIDFromDeclaration(mreg) == hashNew || mreg.strClassID == strClassNew)
                                return state.DoS(0, false, REJECT_DUPLICATE, "house-op-in-mempool");
                        }
                    } else if (!fIncomingRegister && !fTheirsRegister) {
                        uint32_t nTheirs = 0;
                        if (mtx.vchHousePayload.size() >= 4) {
                            memcpy(&nTheirs, mtx.vchHousePayload.data(), 4);
                            if (nTheirs == nHouseIDNewLE)
                                return state.DoS(0, false, REJECT_DUPLICATE, "house-op-in-mempool");
                        }
                    }
                }
                // A governance op on an existing house also conflicts with a
                // pending note MINT/REDEEM for the same house (both change house
                // state; one per house per block). Without this the block
                // template bricks at the ConnectBlock one-op rule. (An incoming
                // REGISTER cannot collide - its house is not in the DB yet.)
                // DEMAND is house-state-NEUTRAL but status-DEPENDENT (valid only
                // while effectively Deferred), so it conflicts too: a recovery
                // ATTEST ordered before a pooled DEMAND in the same template
                // lifts the clause and the demand fails INSIDE TestBlockValidity
                // -> CreateNewBlock throws -> no block ever forms -> the eviction
                // sweep (which runs on tip change) can never heal it. The 3.4
                // permanent-brick class; the guard is the only cure.
                else if (!fIncomingRegister && mtx.nVersion == TRANSACTION_NOTE_VERSION &&
                        (mtx.nNoteOp == NOTE_OP_MINT || mtx.nNoteOp == NOTE_OP_REDEEM || mtx.nNoteOp == NOTE_OP_CLAIM ||
                         mtx.nNoteOp == NOTE_OP_DEMAND) &&
                        mtx.vchNotePayload.size() >= 4) {
                    uint32_t nTheirs = 0;
                    memcpy(&nTheirs, mtx.vchNotePayload.data(), 4); // nHouseID leads every note payload
                    if (nTheirs == nHouseIDNewLE)
                        return state.DoS(0, false, REJECT_DUPLICATE, "house-op-in-mempool");
                }
                // Or a pending deposit ORIGINATE/WITHDRAW/CLAIM for the same house.
                else if (!fIncomingRegister && mtx.nVersion == TRANSACTION_DEPOSIT_VERSION &&
                        (mtx.nDepositOp == DEPOSIT_OP_ORIGINATE || mtx.nDepositOp == DEPOSIT_OP_WITHDRAW ||
                         mtx.nDepositOp == DEPOSIT_OP_CLAIM) && mtx.vchDepositPayload.size() >= 4) {
                    uint32_t nTheirs = 0;
                    memcpy(&nTheirs, mtx.vchDepositPayload.data(), 4); // nHouseID leads every deposit payload
                    if (nTheirs == nHouseIDNewLE)
                        return state.DoS(0, false, REJECT_DUPLICATE, "house-op-in-mempool");
                }
                // Or a pending pool CREATE for the same house: house-state-
                // NEUTRAL but status-DEPENDENT (requires effective-Open, like
                // DEMAND requires Deferred) - a pooled governance op ordered
                // first in the template can invalidate it inside
                // TestBlockValidity (the DR-2 permanent-brick class).
                // ADD/REMOVE/SWAP are status-ungated - no conflict.
                else if (!fIncomingRegister && mtx.nVersion == TRANSACTION_POOL_VERSION &&
                        mtx.nPoolOp == POOL_OP_CREATE && mtx.vchPoolPayload.size() >= 4) {
                    uint32_t nTheirs = 0;
                    memcpy(&nTheirs, mtx.vchPoolPayload.data(), 4); // nPoolID (== nHouseID) leads every pool payload
                    if (nTheirs == nHouseIDNewLE)
                        return state.DoS(0, false, REJECT_DUPLICATE, "house-op-in-mempool");
                }
                // Or a pending pool RETIRE for the same house: it burns X from
                // nMintedUnits (house-state-CHANGING), taking the one-house slot.
                else if (!fIncomingRegister && mtx.nVersion == TRANSACTION_POOL_VERSION &&
                        mtx.nPoolOp == POOL_OP_RETIRE && mtx.vchPoolPayload.size() >= 4) {
                    uint32_t nTheirs = 0;
                    memcpy(&nTheirs, mtx.vchPoolPayload.data(), 4);
                    if (nTheirs == nHouseIDNewLE)
                        return state.DoS(0, false, REJECT_DUPLICATE, "house-op-in-mempool");
                }
            }
        }

        // Contextual note checks. A note MINT/REDEEM changes house state, so -
        // like a house op - two of them for the same house cannot co-reside in
        // the mempool (they would brick our own BMM template at the one-op rule)
        // and one cannot co-reside with a governance op for that house. TRANSFER
        // changes no house state and is unrestricted.
        if (tx.nVersion == TRANSACTION_NOTE_VERSION) {
            uint64_t nNoteUnitsIn = 0;
            for (const CTxIn& in : tx.vin) {
                const Coin& coin = view.AccessCoin(in.prevout);
                if (coin.fNote)
                    nNoteUnitsIn += coin.nNoteUnits;
            }
            auto fnGetHouse = [](uint32_t nID, CHouse& house) { return phousetree->GetHouse(nID, house); };
            // CLAIM escrow/pot lookups resolve against the CONFIRMED chain
            // (escrow coins cannot chain unconfirmed - the one-op-per-house
            // guard blocks a second same-house claim while one is pending).
            auto fnGetCoin = [](const COutPoint& out, Coin& coin) {
                return pcoinsTip->GetCoin(out, coin) && !coin.IsSpent();
            };
            // Reserve-proof recency challenge resolves against the active chain
            // (R-i7; the MINT liveness gate reuses the ATTEST proof primitive).
            auto fnGetBlockHash = [](uint32_t nH, uint256& hash) {
                if ((int64_t)nH > (int64_t)chainActive.Height())
                    return false;
                const CBlockIndex* p = chainActive[(int)nH];
                if (!p)
                    return false;
                hash = p->GetBlockHash();
                return true;
            };
            CHouse houseResult;
            bool fHouseChanged = false;
            // At ATMP the note-input resolver is already CONFIRMED-state (pcoinsTip),
            // which is exactly the parent-state the reserve proof needs, so it doubles
            // as fnGetProofCoin here (a mempool spend of a reserve coin does not evict
            // the mint - it can still ride the next block).
            if (!CheckNoteOperation(tx, state, GetSpendHeight(view), nNoteUnitsIn, fnGetHouse, fnGetCoin, fnGetCoin, fnGetBlockHash, houseResult, fHouseChanged))
                return error("%s: CheckNoteOperation: %s, %s", __func__, tx.GetHash().ToString(), FormatStateMessage(state));

            if (fHouseChanged) {
                const uint32_t nHouseTouched = houseResult.nHouseID;
                for (CTxMemPool::txiter mi = pool.mapTx.begin(); mi != pool.mapTx.end(); mi++) {
                    const CTransaction& mtx = mi->GetTx();
                    // Another note mint/redeem/claim for the same house?
                    if (mtx.nVersion == TRANSACTION_NOTE_VERSION &&
                            (mtx.nNoteOp == NOTE_OP_MINT || mtx.nNoteOp == NOTE_OP_REDEEM || mtx.nNoteOp == NOTE_OP_CLAIM) &&
                            mtx.vchNotePayload.size() >= 4) {
                        uint32_t nTheirs = 0;
                        memcpy(&nTheirs, mtx.vchNotePayload.data(), 4); // nHouseID is the leading field
                        if (nTheirs == nHouseTouched)
                            return state.DoS(0, false, REJECT_DUPLICATE, "note-op-in-mempool");
                    }
                    // A governance op for the same house?
                    else if (mtx.nVersion == TRANSACTION_HOUSE_VERSION && mtx.nHouseOp != HOUSE_OP_REGISTER &&
                            mtx.vchHousePayload.size() >= 4) {
                        uint32_t nTheirs = 0;
                        memcpy(&nTheirs, mtx.vchHousePayload.data(), 4);
                        if (nTheirs == nHouseTouched)
                            return state.DoS(0, false, REJECT_DUPLICATE, "note-op-in-mempool");
                    }
                    // A deposit ORIGINATE/WITHDRAW/CLAIM for the same house also
                    // changes house state (the D accounting) - one op per block.
                    else if (mtx.nVersion == TRANSACTION_DEPOSIT_VERSION &&
                            (mtx.nDepositOp == DEPOSIT_OP_ORIGINATE || mtx.nDepositOp == DEPOSIT_OP_WITHDRAW ||
                             mtx.nDepositOp == DEPOSIT_OP_CLAIM) && mtx.vchDepositPayload.size() >= 4) {
                        uint32_t nTheirs = 0;
                        memcpy(&nTheirs, mtx.vchDepositPayload.data(), 4);
                        if (nTheirs == nHouseTouched)
                            return state.DoS(0, false, REJECT_DUPLICATE, "note-op-in-mempool");
                    }
                    // A pool RETIRE for the same house also changes house state
                    // (it burns X from nMintedUnits) - one house-state change per block.
                    else if (mtx.nVersion == TRANSACTION_POOL_VERSION && mtx.nPoolOp == POOL_OP_RETIRE &&
                            mtx.vchPoolPayload.size() >= 4) {
                        uint32_t nTheirs = 0;
                        memcpy(&nTheirs, mtx.vchPoolPayload.data(), 4);
                        if (nTheirs == nHouseTouched)
                            return state.DoS(0, false, REJECT_DUPLICATE, "note-op-in-mempool");
                    }
                }
            }
            // The mirror of the house-op scan above: an incoming DEMAND is
            // house-state-neutral (fHouseChanged false, so the loop above never
            // runs for it) but STATUS-dependent - a pooled governance op for its
            // house (a recovery ATTEST above all) can invalidate it inside the
            // very template that includes both, which is the permanent-brick
            // ordering. One of the pair must wait a block.
            else if (tx.nNoteOp == NOTE_OP_DEMAND && tx.vchNotePayload.size() >= 4) {
                uint32_t nHouseDemanded = 0;
                memcpy(&nHouseDemanded, tx.vchNotePayload.data(), 4); // nHouseID leads every note payload
                for (CTxMemPool::txiter mi = pool.mapTx.begin(); mi != pool.mapTx.end(); mi++) {
                    const CTransaction& mtx = mi->GetTx();
                    if (mtx.nVersion == TRANSACTION_HOUSE_VERSION && mtx.nHouseOp != HOUSE_OP_REGISTER &&
                            mtx.vchHousePayload.size() >= 4) {
                        uint32_t nTheirs = 0;
                        memcpy(&nTheirs, mtx.vchHousePayload.data(), 4);
                        if (nTheirs == nHouseDemanded)
                            return state.DoS(0, false, REJECT_DUPLICATE, "note-op-in-mempool");
                    }
                }
            }
        }

        // Contextual deposit checks (Phase 3.8). An ORIGINATE/WITHDRAW/CLAIM
        // changes house state (the D accounting), so - like a note MINT - two for
        // the same house cannot co-reside in the mempool (they would brick our own
        // BMM template at the one-op rule), and one cannot co-reside with a
        // governance or note-mint op for that house. TRANSFER changes nothing.
        if (tx.nVersion == TRANSACTION_DEPOSIT_VERSION) {
            auto fnGetHouse = [](uint32_t nID, CHouse& house) { return phousetree->GetHouse(nID, house); };
            auto fnGetCoin = [](const COutPoint& out, Coin& coin) {
                return pcoinsTip->GetCoin(out, coin) && !coin.IsSpent();
            };
            CHouse houseResult;
            bool fHouseChanged = false;
            if (!CheckDepositOperation(tx, state, GetSpendHeight(view), fnGetHouse, fnGetCoin, houseResult, fHouseChanged))
                return error("%s: CheckDepositOperation: %s, %s", __func__, tx.GetHash().ToString(), FormatStateMessage(state));

            if (fHouseChanged) {
                const uint32_t nHouseTouched = houseResult.nHouseID;
                for (CTxMemPool::txiter mi = pool.mapTx.begin(); mi != pool.mapTx.end(); mi++) {
                    const CTransaction& mtx = mi->GetTx();
                    uint32_t nTheirs = 0;
                    bool fTheirsHouseChanging = false;
                    if (mtx.nVersion == TRANSACTION_DEPOSIT_VERSION &&
                            (mtx.nDepositOp == DEPOSIT_OP_ORIGINATE || mtx.nDepositOp == DEPOSIT_OP_WITHDRAW ||
                             mtx.nDepositOp == DEPOSIT_OP_CLAIM) && mtx.vchDepositPayload.size() >= 4) {
                        memcpy(&nTheirs, mtx.vchDepositPayload.data(), 4);
                        fTheirsHouseChanging = true;
                    } else if (mtx.nVersion == TRANSACTION_NOTE_VERSION &&
                            (mtx.nNoteOp == NOTE_OP_MINT || mtx.nNoteOp == NOTE_OP_REDEEM || mtx.nNoteOp == NOTE_OP_CLAIM) &&
                            mtx.vchNotePayload.size() >= 4) {
                        memcpy(&nTheirs, mtx.vchNotePayload.data(), 4);
                        fTheirsHouseChanging = true;
                    } else if (mtx.nVersion == TRANSACTION_HOUSE_VERSION && mtx.nHouseOp != HOUSE_OP_REGISTER &&
                            mtx.vchHousePayload.size() >= 4) {
                        memcpy(&nTheirs, mtx.vchHousePayload.data(), 4);
                        fTheirsHouseChanging = true;
                    } else if (mtx.nVersion == TRANSACTION_POOL_VERSION && mtx.nPoolOp == POOL_OP_RETIRE &&
                            mtx.vchPoolPayload.size() >= 4) {
                        memcpy(&nTheirs, mtx.vchPoolPayload.data(), 4);   // pool RETIRE burns X (house-state-changing)
                        fTheirsHouseChanging = true;
                    }
                    if (fTheirsHouseChanging && nTheirs == nHouseTouched)
                        return state.DoS(0, false, REJECT_DUPLICATE, "deposit-op-in-mempool");
                }
            }
        }

        // Contextual pool checks (Phase 3.7). EVERY pool op moves pool state
        // and binds the pool's priors, so two ops for the same pool cannot
        // co-reside (the loser fails priors INSIDE the template ->
        // CreateNewBlock throws -> permanent BMM brick; the eviction sweep
        // heals post-connect staleness, this guard prevents same-template
        // collisions). A CREATE additionally conflicts with pending
        // governance ops for its house (status-dependent, the DEMAND model).
        if (tx.nVersion == TRANSACTION_POOL_VERSION) {
            auto fnGetPool = [](uint32_t nID, CPool& pool) { return ppooltree->GetPool(nID, pool); };
            auto fnGetHouse = [](uint32_t nID, CHouse& house) { return phousetree->GetHouse(nID, house); };
            CPool poolResult;
            CHouse houseResult;
            bool fHouseChanged = false, fPoolRetired = false;
            if (!CheckPoolOperation(tx, state, GetSpendHeight(view), fnGetPool, fnGetHouse,
                    poolResult, houseResult, fHouseChanged, fPoolRetired))
                return error("%s: CheckPoolOperation: %s, %s", __func__, tx.GetHash().ToString(), FormatStateMessage(state));

            const uint32_t nPoolTouched = poolResult.nPoolID;
            for (CTxMemPool::txiter mi = pool.mapTx.begin(); mi != pool.mapTx.end(); mi++) {
                const CTransaction& mtx = mi->GetTx();
                if (mtx.nVersion == TRANSACTION_POOL_VERSION && mtx.vchPoolPayload.size() >= 4) {
                    uint32_t nTheirs = 0;
                    memcpy(&nTheirs, mtx.vchPoolPayload.data(), 4); // nPoolID leads every pool payload
                    if (nTheirs == nPoolTouched)
                        return state.DoS(0, false, REJECT_DUPLICATE, "pool-op-in-mempool");
                }
                else if (tx.nPoolOp == POOL_OP_CREATE &&
                        mtx.nVersion == TRANSACTION_HOUSE_VERSION && mtx.nHouseOp != HOUSE_OP_REGISTER &&
                        mtx.vchHousePayload.size() >= 4) {
                    uint32_t nTheirs = 0;
                    memcpy(&nTheirs, mtx.vchHousePayload.data(), 4);
                    if (nTheirs == nPoolTouched)
                        return state.DoS(0, false, REJECT_DUPLICATE, "pool-op-in-mempool");
                }
                // An incoming RETIRE burns X from its house (house-state-CHANGING,
                // unlike CREATE/ADD/REMOVE/SWAP), so it also conflicts with any
                // pending governance / note-mint / deposit op for that house: two
                // house-state changes for one house cannot ride one block (the
                // ConnectBlock one-op rule -> a template with both throws in
                // TestBlockValidity -> permanent BMM brick). Pending pool ops on
                // THIS pool are already caught by the first arm above.
                else if (tx.nPoolOp == POOL_OP_RETIRE) {
                    uint32_t nTheirs = 0;
                    bool fTheirsHouseChanging = false;
                    if (mtx.nVersion == TRANSACTION_HOUSE_VERSION && mtx.nHouseOp != HOUSE_OP_REGISTER &&
                            mtx.vchHousePayload.size() >= 4) {
                        memcpy(&nTheirs, mtx.vchHousePayload.data(), 4);
                        fTheirsHouseChanging = true;
                    } else if (mtx.nVersion == TRANSACTION_NOTE_VERSION &&
                            (mtx.nNoteOp == NOTE_OP_MINT || mtx.nNoteOp == NOTE_OP_REDEEM || mtx.nNoteOp == NOTE_OP_CLAIM) &&
                            mtx.vchNotePayload.size() >= 4) {
                        memcpy(&nTheirs, mtx.vchNotePayload.data(), 4);
                        fTheirsHouseChanging = true;
                    } else if (mtx.nVersion == TRANSACTION_DEPOSIT_VERSION &&
                            (mtx.nDepositOp == DEPOSIT_OP_ORIGINATE || mtx.nDepositOp == DEPOSIT_OP_WITHDRAW ||
                             mtx.nDepositOp == DEPOSIT_OP_CLAIM) && mtx.vchDepositPayload.size() >= 4) {
                        memcpy(&nTheirs, mtx.vchDepositPayload.data(), 4);
                        fTheirsHouseChanging = true;
                    }
                    if (fTheirsHouseChanging && nTheirs == nPoolTouched)
                        return state.DoS(0, false, REJECT_DUPLICATE, "pool-op-in-mempool");
                }
            }
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (fRequireStandard && !AreInputsStandard(tx, view))
            return state.Invalid(false, REJECT_NONSTANDARD, "bad-txns-nonstandard-inputs");

        // Check for non-standard witness in P2WSH
        if (tx.HasWitness() && fRequireStandard && !IsWitnessStandard(tx, view))
            return state.DoS(0, false, REJECT_NONSTANDARD, "bad-witness-nonstandard", true);

        int64_t nSigOpsCost = GetTransactionSigOpCost(tx, view, STANDARD_SCRIPT_VERIFY_FLAGS);

        // nModifiedFees includes any fee deltas from PrioritiseTransaction
        CAmount nModifiedFees = nFees;
        pool.ApplyDelta(hash, nModifiedFees);

        // Keep track of transactions that spend a coinbase, which we re-scan
        // during reorgs to ensure COINBASE_MATURITY is still met.
        bool fSpendsCoinbase = false;
        for (const CTxIn &txin : tx.vin) {
            const Coin &coin = view.AccessCoin(txin.prevout);
            if (coin.IsCoinBase()) {
                fSpendsCoinbase = true;
                break;
            }
        }

        // Keep track of transactions that have a withdrawal refund request script
        bool fRefund = false;
        uint256 id;
        for (const CTxOut& o : tx.vout) {
            std::vector<unsigned char> vchSig;
            if (o.scriptPubKey.IsWithdrawalRefundRequest(id, vchSig))
                fRefund = true;
        }

        CTxMemPoolEntry entry(ptx, nFees, nAcceptTime, chainActive.Height(),
                              fSpendsCoinbase, fRefund, id, nSigOpsCost, lp);
        unsigned int nSize = entry.GetTxSize();

        // Check that the transaction doesn't have an excessive number of
        // sigops, making it impossible to mine. Since the coinbase transaction
        // itself can contain sigops MAX_STANDARD_TX_SIGOPS is less than
        // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
        // merely non-standard transaction.
        if (nSigOpsCost > MAX_STANDARD_TX_SIGOPS_COST)
            return state.DoS(0, false, REJECT_NONSTANDARD, "bad-txns-too-many-sigops", false,
                strprintf("%d", nSigOpsCost));

        CAmount mempoolRejectFee = pool.GetMinFee(gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000).GetFee(nSize);
        if (!bypass_limits && mempoolRejectFee > 0 && nModifiedFees < mempoolRejectFee) {
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool min fee not met", false, strprintf("%d < %d", nModifiedFees, mempoolRejectFee));
        }

        // No transactions are allowed below minRelayTxFee except from disconnected blocks
        if (!bypass_limits && nModifiedFees < ::minRelayTxFee.GetFee(nSize)) {
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "min relay fee not met");
        }

        if (nAbsurdFee && nFees > nAbsurdFee)
            return state.Invalid(false,
                REJECT_HIGHFEE, "absurdly-high-fee",
                strprintf("%d > %d", nFees, nAbsurdFee));

        // Calculate in-mempool ancestors, up to a limit.
        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = gArgs.GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = gArgs.GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT)*1000;
        size_t nLimitDescendants = gArgs.GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = gArgs.GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT)*1000;
        std::string errString;
        if (!pool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize, nLimitDescendants, nLimitDescendantSize, errString)) {
            return state.DoS(0, false, REJECT_NONSTANDARD, "too-long-mempool-chain", false, errString);
        }

        // A transaction that spends outputs that would be replaced by it is invalid. Now
        // that we have the set of all ancestors we can detect this
        // pathological case by making sure setConflicts and setAncestors don't
        // intersect.
        for (CTxMemPool::txiter ancestorIt : setAncestors)
        {
            const uint256 &hashAncestor = ancestorIt->GetTx().GetHash();
            if (setConflicts.count(hashAncestor))
            {
                return state.DoS(10, false,
                                 REJECT_INVALID, "bad-txns-spends-conflicting-tx", false,
                                 strprintf("%s spends conflicting transaction %s",
                                           hash.ToString(),
                                           hashAncestor.ToString()));
            }
        }

        // Check if it's economically rational to mine this transaction rather
        // than the ones it replaces.
        CAmount nConflictingFees = 0;
        size_t nConflictingSize = 0;
        uint64_t nConflictingCount = 0;
        CTxMemPool::setEntries allConflicting;

        // If we don't hold the lock allConflicting might be incomplete; the
        // subsequent RemoveStaged() and addUnchecked() calls don't guarantee
        // mempool consistency for us.
        const bool fReplacementTransaction = setConflicts.size();
        if (fReplacementTransaction)
        {
            CFeeRate newFeeRate(nModifiedFees, nSize);
            std::set<uint256> setConflictsParents;
            const int maxDescendantsToVisit = 100;
            CTxMemPool::setEntries setIterConflicting;
            for (const uint256 &hashConflicting : setConflicts)
            {
                CTxMemPool::txiter mi = pool.mapTx.find(hashConflicting);
                if (mi == pool.mapTx.end())
                    continue;

                // Save these to avoid repeated lookups
                setIterConflicting.insert(mi);

                // Don't allow the replacement to reduce the feerate of the
                // mempool.
                //
                // We usually don't want to accept replacements with lower
                // feerates than what they replaced as that would lower the
                // feerate of the next block. Requiring that the feerate always
                // be increased is also an easy-to-reason about way to prevent
                // DoS attacks via replacements.
                //
                // The mining code doesn't (currently) take children into
                // account (CPFP) so we only consider the feerates of
                // transactions being directly replaced, not their indirect
                // descendants. While that does mean high feerate children are
                // ignored when deciding whether or not to replace, we do
                // require the replacement to pay more overall fees too,
                // mitigating most cases.
                CFeeRate oldFeeRate(mi->GetModifiedFee(), mi->GetTxSize());
                if (newFeeRate <= oldFeeRate)
                {
                    return state.DoS(0, false,
                            REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                            strprintf("rejecting replacement %s; new feerate %s <= old feerate %s",
                                  hash.ToString(),
                                  newFeeRate.ToString(),
                                  oldFeeRate.ToString()));
                }

                for (const CTxIn &txin : mi->GetTx().vin)
                {
                    setConflictsParents.insert(txin.prevout.hash);
                }

                nConflictingCount += mi->GetCountWithDescendants();
            }
            // This potentially overestimates the number of actual descendants
            // but we just want to be conservative to avoid doing too much
            // work.
            if (nConflictingCount <= maxDescendantsToVisit) {
                // If not too many to replace, then calculate the set of
                // transactions that would have to be evicted
                for (CTxMemPool::txiter it : setIterConflicting) {
                    pool.CalculateDescendants(it, allConflicting);
                }
                for (CTxMemPool::txiter it : allConflicting) {
                    nConflictingFees += it->GetModifiedFee();
                    nConflictingSize += it->GetTxSize();
                }
            } else {
                return state.DoS(0, false,
                        REJECT_NONSTANDARD, "too many potential replacements", false,
                        strprintf("rejecting replacement %s; too many potential replacements (%d > %d)\n",
                            hash.ToString(),
                            nConflictingCount,
                            maxDescendantsToVisit));
            }

            for (unsigned int j = 0; j < tx.vin.size(); j++)
            {
                // We don't want to accept replacements that require low
                // feerate junk to be mined first. Ideally we'd keep track of
                // the ancestor feerates and make the decision based on that,
                // but for now requiring all new inputs to be confirmed works.
                if (!setConflictsParents.count(tx.vin[j].prevout.hash))
                {
                    // Rather than check the UTXO set - potentially expensive -
                    // it's cheaper to just check if the new input refers to a
                    // tx that's in the mempool.
                    if (pool.mapTx.find(tx.vin[j].prevout.hash) != pool.mapTx.end())
                        return state.DoS(0, false,
                                         REJECT_NONSTANDARD, "replacement-adds-unconfirmed", false,
                                         strprintf("replacement %s adds unconfirmed input, idx %d",
                                                  hash.ToString(), j));
                }
            }

            // The replacement must pay greater fees than the transactions it
            // replaces - if we did the bandwidth used by those conflicting
            // transactions would not be paid for.
            if (nModifiedFees < nConflictingFees)
            {
                return state.DoS(0, false,
                                 REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                                 strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
                                          hash.ToString(), FormatMoney(nModifiedFees), FormatMoney(nConflictingFees)));
            }

            // Finally in addition to paying more fees than the conflicts the
            // new transaction must pay for its own bandwidth.
            CAmount nDeltaFees = nModifiedFees - nConflictingFees;
            if (nDeltaFees < ::incrementalRelayFee.GetFee(nSize))
            {
                return state.DoS(0, false,
                        REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                        strprintf("rejecting replacement %s, not enough additional fees to relay; %s < %s",
                              hash.ToString(),
                              FormatMoney(nDeltaFees),
                              FormatMoney(::incrementalRelayFee.GetFee(nSize))));
            }
        }

        unsigned int scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;
        if (!chainparams.RequireStandard()) {
            scriptVerifyFlags = gArgs.GetArg("-promiscuousmempoolflags", scriptVerifyFlags);
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        PrecomputedTransactionData txdata(tx);
        if (!CheckInputs(tx, state, view, true, scriptVerifyFlags, true, false, txdata)) {
            // SCRIPT_VERIFY_CLEANSTACK requires SCRIPT_VERIFY_WITNESS, so we
            // need to turn both off, and compare against just turning off CLEANSTACK
            // to see if the failure is specifically due to witness validation.
            CValidationState stateDummy; // Want reported failures to be from first CheckInputs
            if (!tx.HasWitness() && CheckInputs(tx, stateDummy, view, true, scriptVerifyFlags & ~(SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CLEANSTACK), true, false, txdata) &&
                !CheckInputs(tx, stateDummy, view, true, scriptVerifyFlags & ~SCRIPT_VERIFY_CLEANSTACK, true, false, txdata)) {
                // Only the witness is missing, so the transaction itself may be fine.
                state.SetCorruptionPossible();
            }
            return false; // state filled in by CheckInputs
        }

        // Check again against the current block tip's script verification
        // flags to cache our script execution flags. This is, of course,
        // useless if the next block has different script flags from the
        // previous one, but because the cache tracks script flags for us it
        // will auto-invalidate and we'll just have a few blocks of extra
        // misses on soft-fork activation.
        //
        // This is also useful in case of bugs in the standard flags that cause
        // transactions to pass as valid when they're actually invalid. For
        // instance the STRICTENC flag was incorrectly allowing certain
        // CHECKSIG NOT scripts to pass, even though they were invalid.
        //
        // There is a similar check in CreateNewBlock() to prevent creating
        // invalid blocks (using TestBlockValidity), however allowing such
        // transactions into the mempool can be exploited as a DoS attack.
        unsigned int currentBlockScriptVerifyFlags = GetBlockScriptFlags(chainActive.Tip(), Params().GetConsensus());
        if (!CheckInputsFromMempoolAndCache(tx, state, view, pool, currentBlockScriptVerifyFlags, true, txdata))
        {
            // If we're using promiscuousmempoolflags, we may hit this normally
            // Check if current block has some flags that scriptVerifyFlags
            // does not before printing an ominous warning
            if (!(~scriptVerifyFlags & currentBlockScriptVerifyFlags)) {
                return error("%s: BUG! PLEASE REPORT THIS! ConnectInputs failed against latest-block but not STANDARD flags %s, %s",
                    __func__, hash.ToString(), FormatStateMessage(state));
            } else {
                if (!CheckInputs(tx, state, view, true, MANDATORY_SCRIPT_VERIFY_FLAGS, true, false, txdata)) {
                    return error("%s: ConnectInputs failed against MANDATORY but not STANDARD flags due to promiscuous mempool %s, %s",
                        __func__, hash.ToString(), FormatStateMessage(state));
                } else {
                    LogPrintf("Warning: -promiscuousmempool flags set to not include currently enforced soft forks, this may break mining or otherwise cause instability!\n");
                }
            }
        }

        // Remove conflicting transactions from the mempool
        for (const CTxMemPool::txiter it : allConflicting)
        {
            LogPrint(BCLog::MEMPOOL, "replacing tx %s with %s for %s BTC additional fees, %d delta bytes\n",
                    it->GetTx().GetHash().ToString(),
                    hash.ToString(),
                    FormatMoney(nModifiedFees - nConflictingFees),
                    (int)nSize - (int)nConflictingSize);
            if (plTxnReplaced)
                plTxnReplaced->push_back(it->GetSharedTx());
        }
        pool.RemoveStaged(allConflicting, false, MemPoolRemovalReason::REPLACED);

        // This transaction should only count for fee estimation if:
        // - it isn't a BIP 125 replacement transaction (may not be widely supported)
        // - it's not being readded during a reorg which bypasses typical mempool fee limits
        // - the node is not behind
        // - the transaction is not dependent on any other transactions in the mempool
        bool validForFeeEstimation = !fReplacementTransaction && !bypass_limits && IsCurrentForFeeEstimation() && pool.HasNoInputsOf(tx);

        // Store transaction in memory
        pool.addUnchecked(hash, entry, setAncestors, validForFeeEstimation);

        // trim mempool and check if tx was trimmed
        if (!bypass_limits) {
            LimitMempoolSize(pool, gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
            if (!pool.exists(hash))
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool full");
        }
    }

    GetMainSignals().TransactionAddedToMempool(ptx);

    return true;
}

/** (try to) add transaction to memory pool with a specified acceptance time **/
static bool AcceptToMemoryPoolWithTime(const CChainParams& chainparams, CTxMemPool& pool, CValidationState &state, const CTransactionRef &tx,
                        bool* pfMissingInputs, int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced,
                        bool bypass_limits, const CAmount nAbsurdFee)
{
    std::vector<COutPoint> coins_to_uncache;
    bool res = AcceptToMemoryPoolWorker(chainparams, pool, state, tx, pfMissingInputs, nAcceptTime, plTxnReplaced, bypass_limits, nAbsurdFee, coins_to_uncache);
    if (!res) {
        for (const COutPoint& hashTx : coins_to_uncache)
            pcoinsTip->Uncache(hashTx);
    }
    // After we've (potentially) uncached entries, ensure our coins cache is still within its size limits
    CValidationState stateDummy;
    FlushStateToDisk(chainparams, stateDummy, FLUSH_STATE_PERIODIC);
    return res;
}

bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState &state, const CTransactionRef &tx,
                        bool* pfMissingInputs, std::list<CTransactionRef>* plTxnReplaced,
                        bool bypass_limits, const CAmount nAbsurdFee)
{
    const CChainParams& chainparams = Params();
    return AcceptToMemoryPoolWithTime(chainparams, pool, state, tx, pfMissingInputs, GetTime(), plTxnReplaced, bypass_limits, nAbsurdFee);
}

/**
 * Return transaction in txOut, and if it was found inside a block, its hash is placed in hashBlock.
 * If blockIndex is provided, the transaction is fetched from the corresponding block.
 */
bool GetTransaction(const uint256& hash, CTransactionRef& txOut, const Consensus::Params& consensusParams, uint256& hashBlock, bool fAllowSlow, CBlockIndex* blockIndex)
{
    CBlockIndex* pindexSlow = blockIndex;

    LOCK(cs_main);

    if (!blockIndex) {
        CTransactionRef ptx = mempool.get(hash);
        if (ptx) {
            txOut = ptx;
            return true;
        }

        if (fTxIndex) {
            CDiskTxPos postx;
            if (pblocktree->ReadTxIndex(hash, postx)) {
                CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
                if (file.IsNull())
                    return error("%s: OpenBlockFile failed", __func__);
                CBlockHeader header;
                try {
                    file >> header;
                    fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
                    file >> txOut;
                } catch (const std::exception& e) {
                    return error("%s: Deserialize or I/O error - %s", __func__, e.what());
                }
                hashBlock = header.GetHash();
                if (txOut->GetHash() != hash)
                    return error("%s: txid mismatch", __func__);
                return true;
            }

            // transaction not found in index, nothing more can be done
            return false;
        }

        if (fAllowSlow) { // use coin database to locate block that contains transaction, and scan it
            const Coin& coin = AccessByTxid(*pcoinsTip, hash);
            if (!coin.IsSpent()) pindexSlow = chainActive[coin.nHeight];
        }
    }

    if (pindexSlow) {
        CBlock block;
        if (ReadBlockFromDisk(block, pindexSlow, consensusParams)) {
            for (const auto& tx : block.vtx) {
                if (tx->GetHash() == hash) {
                    txOut = tx;
                    hashBlock = pindexSlow->GetBlockHash();
                    return true;
                }
            }
        }
    }

    return false;
}






//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

static bool WriteBlockToDisk(const CBlock& block, CDiskBlockPos& pos, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("WriteBlockToDisk: OpenBlockFile failed");

    // Write index header
    unsigned int nSize = GetSerializeSize(fileout, block);
    fileout << FLATDATA(messageStart) << nSize;

    // Write block
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("WriteBlockToDisk: ftell failed");
    pos.nPos = (unsigned int)fileOutPos;
    fileout << block;

    return true;
}

bool ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos, const Consensus::Params& consensusParams)
{
    block.SetNull();

    // Open history file to read
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("ReadBlockFromDisk: OpenBlockFile failed for %s", pos.ToString());

    // Read block
    try {
        filein >> block;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), pos.ToString());
    }

    return true;
}

bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams)
{
    CDiskBlockPos blockPos;
    {
        LOCK(cs_main);
        blockPos = pindex->GetBlockPos();
    }

    if (!ReadBlockFromDisk(block, blockPos, consensusParams))
        return false;
    if (block.GetHash() != pindex->GetBlockHash())
        return error("ReadBlockFromDisk(CBlock&, CBlockIndex*): GetHash() doesn't match index for %s at %s",
                pindex->ToString(), pindex->GetBlockPos().ToString());
    return true;
}

CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams)
{
    return 0;
}

bool IsInitialBlockDownload()
{
    // Once this function has returned false, it must remain false.
    static std::atomic<bool> latchToFalse{false};
    // Optimization: pre-test latch before taking the lock.
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;

    LOCK(cs_main);
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;
    if (fImporting || fReindex)
        return true;
    if (chainActive.Tip() == nullptr)
        return true;
    if (chainActive.Tip()->GetBlockTime() < (GetTime() - nMaxTipAge))
        return true;
    LogPrintf("Leaving InitialBlockDownload (latching to false)\n");
    latchToFalse.store(true, std::memory_order_relaxed);
    return false;
}

CBlockIndex *pindexBestForkTip = nullptr, *pindexBestForkBase = nullptr;

static void AlertNotify(const std::string& strMessage)
{
    uiInterface.NotifyAlertChanged();
    std::string strCmd = gArgs.GetArg("-alertnotify", "");
    if (strCmd.empty()) return;

    // Alert text should be plain ascii coming from a trusted source, but to
    // be safe we first strip anything not in safeChars, then add single quotes around
    // the whole string before passing it to the shell:
    std::string singleQuote("'");
    std::string safeStatus = SanitizeString(strMessage);
    safeStatus = singleQuote+safeStatus+singleQuote;
    boost::replace_all(strCmd, "%s", safeStatus);

    std::thread t(runCommand, strCmd);
    t.detach(); // thread runs free
}

static void CheckForkWarningConditions()
{
    AssertLockHeld(cs_main);
    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before finishing our initial sync)
    if (IsInitialBlockDownload())
        return;

    // If our best fork is no longer within 72 blocks (+/- 12 hours if no one mines it)
    // of our head, drop it
    if (pindexBestForkTip && chainActive.Height() - pindexBestForkTip->nHeight >= 72)
        pindexBestForkTip = nullptr;

    if (pindexBestForkTip)
    {
        if (pindexBestForkTip && pindexBestForkBase)
        {
            LogPrintf("%s: Warning: Large valid fork found\n  forking the chain at height %d (%s)\n  lasting to height %d (%s).\nChain state database corruption likely.\n", __func__,
                   pindexBestForkBase->nHeight, pindexBestForkBase->phashBlock->ToString(),
                   pindexBestForkTip->nHeight, pindexBestForkTip->phashBlock->ToString());
            SetfLargeWorkForkFound(true);
        }
        else
        {
            LogPrintf("%s: Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state database corruption likely.\n", __func__);
            SetfLargeWorkInvalidChainFound(true);
        }
    }
    else
    {
        SetfLargeWorkForkFound(false);
        SetfLargeWorkInvalidChainFound(false);
    }
}

static void CheckForkWarningConditionsOnNewFork(CBlockIndex* pindexNewForkTip)
{
    AssertLockHeld(cs_main);
    // If we are on a fork that is sufficiently large, set a warning flag
    CBlockIndex* pfork = pindexNewForkTip;
    CBlockIndex* plonger = chainActive.Tip();
    while (pfork && pfork != plonger)
    {
        while (plonger && plonger->nHeight > pfork->nHeight)
            plonger = plonger->pprev;
        if (pfork == plonger)
            break;
        pfork = pfork->pprev;
    }

    // We define a condition where we should warn the user about as a fork of at least 7 blocks
    // with a tip within 72 blocks (+/- 12 hours if no one mines it) of ours
    // We use 7 blocks rather arbitrarily as it represents just under 10% of sustained network
    // hash rate operating on the fork.
    // or a chain that is entirely longer than ours and invalid (note that this should be detected by both)
    // We define it this way because it allows us to only store the highest fork tip (+ base) which meets
    // the 7-block condition and from this always have the most-likely-to-cause-warning fork
    if (pfork && (!pindexBestForkTip || pindexNewForkTip->nHeight > pindexBestForkTip->nHeight) &&
            chainActive.Height() - pindexNewForkTip->nHeight < 72)
    {
        pindexBestForkTip = pindexNewForkTip;
        pindexBestForkBase = pfork;
    }

    CheckForkWarningConditions();
}

void static InvalidChainFound(CBlockIndex* pindexNew)
{
    if (!pindexBestInvalid)
        pindexBestInvalid = pindexNew;

    LogPrintf("%s: invalid block=%s  height=%d  date=%s\n", __func__,
      pindexNew->GetBlockHash().ToString(), pindexNew->nHeight,
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S",
      pindexNew->GetBlockTime()));
    CBlockIndex *tip = chainActive.Tip();
    assert (tip);
    LogPrintf("%s:  current best=%s  height=%d  date=%s\n", __func__,
      tip->GetBlockHash().ToString(), chainActive.Height(),
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", tip->GetBlockTime()));
    CheckForkWarningConditions();
}

void CChainState::InvalidBlockFound(CBlockIndex *pindex, const CValidationState &state) {
    if (!state.CorruptionPossible()) {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        g_failed_blocks.insert(pindex);
        setDirtyBlockIndex.insert(pindex);
        setBlockIndexCandidates.erase(pindex);
        InvalidChainFound(pindex);
    }
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, CTxUndo &txundo, int nHeight, CAmount& amountAssetInOut, int& nControlNOut, uint32_t& nAssetIDOut, uint32_t nNewAssetIDIn, uint32_t nNewBillIDIn, uint32_t nNewHouseIDIn)
{
    amountAssetInOut = CAmount(0); // Track asset inputs
    nControlNOut = -1; // Track asset controller outputs
    nAssetIDOut = 0; // Track asset ID
    uint32_t nBillIDSpent = 0; // Track a spent bill title (endorsement)
    uint32_t nHouseIDSpent = 0; // Track a spent house pledge (reclaim)
    if (!tx.IsCoinBase()) {
        txundo.vprevout.reserve(tx.vin.size());
        // mark inputs spent
        for (size_t x = 0; x < tx.vin.size(); x++) {
            txundo.vprevout.emplace_back();
            bool fBitAsset = false;
            bool fBitAssetControl = false;
            uint32_t nAssetID = 0;
            bool is_spent = inputs.SpendCoin(tx.vin[x].prevout, fBitAsset, fBitAssetControl, nAssetID, &txundo.vprevout.back());

            // Update nAssetIDOut if SpendCoin returns a non-zero asset ID
            if (nAssetID)
                nAssetIDOut = nAssetID;

            assert(is_spent);

            if (fBitAsset)
                amountAssetInOut += txundo.vprevout.back().out.nValue;

            if (fBitAssetControl)
                nControlNOut = x;

            if (txundo.vprevout.back().fBill)
                nBillIDSpent = txundo.vprevout.back().nBillID;

            if (txundo.vprevout.back().fHouseEscrow)
                nHouseIDSpent = txundo.vprevout.back().nHouseID;
        }
    }

    // add outputs
    const uint32_t nBillID = nNewBillIDIn ? nNewBillIDIn : nBillIDSpent;
    const uint32_t nHouseID = nNewHouseIDIn ? nNewHouseIDIn : nHouseIDSpent;
    AddCoins(inputs, tx, nHeight, nAssetIDOut, amountAssetInOut, nControlNOut, nNewAssetIDIn, nBillID, nHouseID);
}

/**
 * Contextual validation of a bill operation against bill state supplied by
 * the caller (BillDB directly for the mempool; BillDB plus this block's
 * pending bills for ConnectBlock). On success billOut holds the resulting
 * bill record: the new bill for ISSUE (nBillID unassigned), or the mutated
 * bill for ENDORSE / RETIRE / CLAIM. Shape and payload-signature checks that
 * need no context live in CheckBillTransactionShape (CheckTransaction).
 */
bool CheckBillOperation(const CTransaction& tx, CValidationState& state, int nHeight, const CAmount& nTxFee,
                        const std::function<bool(uint32_t, CBill&)>& fnGetBill,
                        const std::function<bool(const uint256&)>& fnHaveBillHash,
                        CBill& billOut)
{
    if (tx.nBillOp == BILL_OP_ISSUE) {
        BillIssue issue;
        if (!DecodeBillPayload(tx.vchBillPayload, issue))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-payload");

        // Shape (CheckTransaction) guarantees >= 2 outputs before we get here;
        // guard anyway so this contextual check is self-contained.
        if (tx.vout.size() < 2)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-vout-size");

        const uint256 billID = BillIDFromBody(issue.vchEncryptedBody);
        if (fnHaveBillHash(billID))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-duplicate");

        if (issue.nMaturityHeight <= (uint32_t)nHeight)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-maturity-past");

        // Bound the tenor. Computed in uint64 so the addition cannot wrap; with
        // the grace cap this keeps maturity + grace well inside uint32 (closes
        // the CLAIM-gate overflow).
        if ((uint64_t)issue.nMaturityHeight > (uint64_t)nHeight + MAX_BILL_TENOR_BLOCKS)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-tenor");

        // Outer-record signatures. These two ECDSA verifies live here (a
        // contextual check that runs AFTER Consensus::CheckTxInputs) rather than
        // in the context-free CheckTransaction path, so a stream of orphan v11
        // txs with non-existent inputs cannot force free signature work. The
        // acceptor signature IS the acceptance (D5). Binding tx.vout[1].nValue
        // stops a relay observer from replaying the payload with a token escrow
        // bond (the bond is the holder's default-recovery collateral).
        const uint256 sighash = BillIssueSigHash(billID, issue.amount,
                tx.vout[1].nValue, issue.nMaturityHeight, issue.nGraceBlocks,
                issue.vchDrawerPubKey, issue.vchAcceptorPubKey, issue.vchHolderPubKey);
        if (!CPubKey(issue.vchDrawerPubKey).Verify(sighash, issue.vchDrawerSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-drawer-sig");
        if (!CPubKey(issue.vchAcceptorPubKey).Verify(sighash, issue.vchAcceptorSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-acceptor-sig");

        billOut = CBill();
        billOut.billID = billID;
        billOut.vchEncryptedBody = issue.vchEncryptedBody;
        billOut.amount = issue.amount;
        billOut.amountEscrow = tx.vout[1].nValue;
        billOut.nIssuedHeight = nHeight;
        billOut.nMaturityHeight = issue.nMaturityHeight;
        billOut.nGraceBlocks = issue.nGraceBlocks;
        billOut.vchDrawerPubKey = issue.vchDrawerPubKey;
        billOut.vchAcceptorPubKey = issue.vchAcceptorPubKey;
        billOut.vchHolderPubKey = issue.vchHolderPubKey;
        billOut.status = BILL_STATUS_ACTIVE;
        billOut.txidIssue = tx.GetHash();
        billOut.outEscrow = COutPoint(tx.GetHash(), 1);
        billOut.outTitle = COutPoint(tx.GetHash(), 0);
        return true;
    }

    if (tx.nBillOp == BILL_OP_ENDORSE) {
        BillEndorse endorse;
        if (!DecodeBillPayload(tx.vchBillPayload, endorse))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-endorse-payload");

        CBill bill;
        if (!fnGetBill(endorse.nBillID, bill))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-unknown");
        if (bill.status != BILL_STATUS_ACTIVE)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-endorse-inactive");
        if (endorse.endorsement.vchFrom != bill.vchHolderPubKey)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-endorse-not-holder");

        // The recorded height must be at or slightly below the connection
        // height (records stay accurate; txs survive small reorgs)
        const uint32_t nAtHeight = endorse.endorsement.nAtHeight;
        if (nAtHeight > (uint32_t)nHeight || (uint32_t)nHeight - nAtHeight > BILL_ENDORSE_HEIGHT_SLACK)
            return state.DoS(10, false, REJECT_INVALID, "bad-bill-endorse-height");

        const uint256 sighash = BillEndorseSigHash(bill.billID, endorse.endorsement.vchTo, nAtHeight);
        if (!CPubKey(endorse.endorsement.vchFrom).Verify(sighash, endorse.endorsement.vchSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-endorse-sig");

        // Fee escalation past the soft cap (Tx-4)
        if (nTxFee < BillEndorseFeeFloor(bill.vEndorsement.size() + 1))
            return state.DoS(10, false, REJECT_INVALID, "bad-bill-endorse-fee");

        billOut = bill;
        billOut.vEndorsement.push_back(endorse.endorsement);
        billOut.vchHolderPubKey = endorse.endorsement.vchTo;
        billOut.outTitle = COutPoint(tx.GetHash(), 0);
        return true;
    }

    if (tx.nBillOp == BILL_OP_RETIRE) {
        BillRetire retire;
        if (!DecodeBillPayload(tx.vchBillPayload, retire))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-retire-payload");

        CBill bill;
        if (!fnGetBill(retire.nBillID, bill))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-unknown");
        if (bill.status != BILL_STATUS_ACTIVE)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-retire-inactive");

        const uint256 sighash = BillRetireSigHash(bill.billID, BillHashOutputs(tx));
        if (!CPubKey(bill.vchAcceptorPubKey).Verify(sighash, retire.vchAcceptorSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-retire-sig");

        // Retirement is the drawee paying face to the current holder
        if (BillValuePaidTo(tx, bill.vchHolderPubKey) < bill.amount)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-retire-payment");

        billOut = bill;
        billOut.status = BILL_STATUS_RETIRED;
        return true;
    }

    if (tx.nBillOp == BILL_OP_CLAIM) {
        BillClaim claim;
        if (!DecodeBillPayload(tx.vchBillPayload, claim))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-claim-payload");

        CBill bill;
        if (!fnGetBill(claim.nBillID, bill))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-unknown");
        if (bill.status != BILL_STATUS_ACTIVE)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-claim-inactive");

        // Default: only past maturity + grace (uint64 sum - cannot wrap)
        if ((uint64_t)nHeight <= (uint64_t)bill.nMaturityHeight + bill.nGraceBlocks)
            return state.DoS(10, false, REJECT_INVALID, "bad-bill-claim-early");

        // The holder signs the exact output set - where the escrow goes is
        // the holder's choice, the signature is the authorization
        const uint256 sighash = BillClaimSigHash(bill.billID, BillHashOutputs(tx));
        if (!CPubKey(bill.vchHolderPubKey).Verify(sighash, claim.vchHolderSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-claim-sig");

        billOut = bill;
        billOut.status = BILL_STATUS_DEFAULTED;
        return true;
    }

    return state.DoS(100, false, REJECT_INVALID, "bad-bill-op");
}


/** Verify exactly nRequired approver signatures from ACTIVE partners over
 * sighash. Indices are strictly-ascending (shape-checked) and must point at
 * active members of the CURRENT partner set. */
static bool VerifyHouseApprovers(const CHouse& house, const std::vector<uint32_t>& vIndex,
                                 const std::vector<std::vector<unsigned char>>& vSig,
                                 const uint256& sighash, uint32_t nRequired,
                                 CValidationState& state, const char* reject)
{
    // Independent of CheckApproverShape (defense-in-depth): the "M distinct
    // signers" guarantee must not rest solely on the shape gate running first.
    // Require exactly nRequired (indices, sigs) and strictly-ascending indices
    // here too, so a future refactor can't silently open a single-signer forge.
    if (vIndex.size() != nRequired || vSig.size() != nRequired)
        return state.DoS(100, false, REJECT_INVALID, reject);

    for (size_t i = 0; i < vIndex.size(); i++) {
        if (i > 0 && vIndex[i] <= vIndex[i - 1])
            return state.DoS(100, false, REJECT_INVALID, reject);
        if (vIndex[i] >= house.vPartner.size())
            return state.DoS(100, false, REJECT_INVALID, reject);
        const HousePartner& p = house.vPartner[vIndex[i]];
        if (p.status != HOUSE_PARTNER_ACTIVE)
            return state.DoS(100, false, REJECT_INVALID, reject);
        if (!CPubKey(p.vchPubKey).Verify(sighash, vSig[i]))
            return state.DoS(100, false, REJECT_INVALID, reject);
    }
    return true;
}

/** House on-chain liabilities: outstanding note units (Phase 3.2) + term
 * deposits (5A, still 0). Backs the WINDDOWN gate so a house cannot abandon
 * live notes and reclaim its escrow. */
static CAmount GetHouseLiabilities(const CHouse& house)
{
    // Notes (N) + term deposits (D, Phase 3.8): both are on-chain liabilities the
    // WINDDOWN / final-settle gates must see as outstanding.
    return (CAmount)house.nMintedUnits + (CAmount)house.nDepositUnits;
}

bool CheckHouseOperation(const CTransaction& tx, CValidationState& state, int nHeight,
                         const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                         const std::function<bool(const uint256&)>& fnHaveHouseHash,
                         const std::function<bool(const std::string&)>& fnHaveClassID,
                         const std::function<bool(const COutPoint&, Coin&)>& fnGetProofCoin,
                         const std::function<bool(uint32_t, uint256&)>& fnGetBlockHash,
                         CHouse& houseOut)
{
    if (tx.nHouseOp == HOUSE_OP_REGISTER) {
        HouseRegister reg;
        if (!DecodeHousePayload(tx.vchHousePayload, reg))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-register-payload");

        const uint256 houseID = HouseIDFromDeclaration(reg);
        if (fnHaveHouseHash(houseID))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-duplicate");
        if (fnHaveClassID(reg.strClassID))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-classid-taken");

        // Founding-partner signatures: each binds the full declaration plus
        // that partner's own pledge (index + amount). These N ECDSA verifies
        // run here - contextually, AFTER Consensus::CheckTxInputs - so orphan
        // v12 spam cannot force free signature work (Bills DoS pricing).
        const uint256 declDigest = HouseDeclarationDigest(reg);
        for (size_t i = 0; i < reg.vPartnerPubKey.size(); i++) {
            const uint256 sighash = HouseRegisterSigHash(declDigest, i, reg.vPledgeAmount[i]);
            if (!CPubKey(reg.vPartnerPubKey[i]).Verify(sighash, reg.vPartnerSig[i]))
                return state.DoS(100, false, REJECT_INVALID, "bad-house-register-sig");
        }

        houseOut = CHouse();
        houseOut.houseID = houseID;
        houseOut.nTier = reg.nTier;
        houseOut.nThresholdM = reg.nThresholdM;
        houseOut.strClassID = reg.strClassID;
        houseOut.nDenomMgGold = reg.nDenomMgGold;
        houseOut.vchRedemptionDestPK = reg.vchRedemptionDestPK;
        houseOut.status = HOUSE_STATUS_OPEN;
        houseOut.nRegisteredHeight = nHeight;
        // Attestation clock starts at registration: the house has one full
        // miss-window (MISS_N * CADENCE blocks) of grace before lazy stress.
        houseOut.nLastAttestHeight = nHeight;
        houseOut.txidRegister = tx.GetHash();
        for (size_t i = 0; i < reg.vPartnerPubKey.size(); i++) {
            HousePartner partner;
            partner.vchPubKey = reg.vPartnerPubKey[i];
            partner.amountPledge = reg.vPledgeAmount[i];
            partner.vOutPledge.push_back(COutPoint(tx.GetHash(), i));
            partner.status = HOUSE_PARTNER_ACTIVE;
            houseOut.vPartner.push_back(partner);
        }
        return true;
    }

    if (tx.nHouseOp == HOUSE_OP_TOPUP) {
        HouseTopup topup;
        if (!DecodeHousePayload(tx.vchHousePayload, topup))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-topup-payload");

        CHouse house;
        if (!fnGetHouse(topup.nHouseID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-unknown");
        // Top-up is RECOVERY CAPITAL: allowed while effectively Open, Stressed
        // OR Deferred (restoring the house is the entire purpose of the
        // suspension window), blocked once wound down or (lazily) insolvent.
        {
            const char chEff = HouseEffectiveStatus(house, nHeight);
            if (chEff != HOUSE_STATUS_OPEN && chEff != HOUSE_STATUS_STRESSED &&
                    chEff != HOUSE_STATUS_DEFERRED)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-topup-closed");
        }
        if (topup.nPartnerIndex >= house.vPartner.size())
            return state.DoS(100, false, REJECT_INVALID, "bad-house-topup-partner");
        HousePartner& partner = house.vPartner[topup.nPartnerIndex];
        if (partner.status != HOUSE_PARTNER_ACTIVE)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-topup-partner-tail");
        // Bound pledge outpoints per partner (record size + RECLAIM scan)
        if (partner.vOutPledge.size() >= MAX_HOUSE_PLEDGE_OUTPOINTS)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-topup-outpoint-cap");

        if (tx.vout[0].scriptPubKey != HouseEscrowScript(house.houseID))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-topup-escrow");

        // Signature binds the exact output set (escrow value + destination)
        const uint256 sighash = HouseTopupSigHash(house.houseID, topup.nPartnerIndex, BillHashOutputs(tx));
        if (!CPubKey(partner.vchPubKey).Verify(sighash, topup.vchSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-topup-sig");

        partner.amountPledge += tx.vout[0].nValue;
        partner.vOutPledge.push_back(COutPoint(tx.GetHash(), 0));
        // Canonical order: the RECLAIM undo path sorts restored lists, so
        // every write path must sort too or reorged and fresh-synced nodes
        // end with byte-divergent records.
        std::sort(partner.vOutPledge.begin(), partner.vOutPledge.end());
        houseOut = house;
        return true;
    }

    if (tx.nHouseOp == HOUSE_OP_ADMIT) {
        HouseAdmit admit;
        if (!DecodeHousePayload(tx.vchHousePayload, admit))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-admit-payload");

        CHouse house;
        if (!fnGetHouse(admit.nHouseID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-unknown");
        // Membership changes not mid-stress: effective Open strictly
        if (HouseEffectiveStatus(house, nHeight) != HOUSE_STATUS_OPEN)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-admit-closed");
        // Admission gate is the tier-3 mechanism; tier 2 sets are immutable
        if (house.nTier != HOUSE_TIER_MULTI_PARTNER)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-admit-tier");
        if (house.vPartner.size() >= MAX_HOUSE_PARTNERS)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-admit-full");
        for (const HousePartner& p : house.vPartner) {
            if (p.vchPubKey == admit.vchNewPubKey)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-admit-already-partner");
        }
        if (tx.vout[0].scriptPubKey != HouseEscrowScript(house.houseID))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-admit-escrow");

        // New partner accepts (binds own key + pledge); M active partners approve
        const uint256 sighash = HouseAdmitSigHash(house.houseID, admit.vchNewPubKey, tx.vout[0].nValue);
        if (!CPubKey(admit.vchNewPubKey).Verify(sighash, admit.vchNewSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-admit-new-sig");
        if (!VerifyHouseApprovers(house, admit.vApproverIndex, admit.vApproverSig, sighash,
                house.nThresholdM, state, "bad-house-admit-approver"))
            return false;

        HousePartner partner;
        partner.vchPubKey = admit.vchNewPubKey;
        partner.amountPledge = tx.vout[0].nValue;
        partner.vOutPledge.push_back(COutPoint(tx.GetHash(), 0));
        partner.status = HOUSE_PARTNER_ACTIVE;
        house.vPartner.push_back(partner);
        houseOut = house;
        return true;
    }

    if (tx.nHouseOp == HOUSE_OP_EXIT) {
        HouseExit ex;
        if (!DecodeHousePayload(tx.vchHousePayload, ex))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-exit-payload");

        CHouse house;
        if (!fnGetHouse(ex.nHouseID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-unknown");
        // No partner leaves mid-stress (escrow is the loss-absorbing layer
        // the stress machinery exists to hold in place): effective Open only
        if (HouseEffectiveStatus(house, nHeight) != HOUSE_STATUS_OPEN)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-exit-closed");
        // Individual exit is a tier-3 affordance (tier-2 sets are fixed;
        // solo houses leave via WINDDOWN)
        if (house.nTier != HOUSE_TIER_MULTI_PARTNER)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-exit-tier");
        if (ex.nPartnerIndex >= house.vPartner.size())
            return state.DoS(100, false, REJECT_INVALID, "bad-house-exit-partner");
        HousePartner& partner = house.vPartner[ex.nPartnerIndex];
        if (partner.status != HOUSE_PARTNER_ACTIVE)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-exit-partner-tail");
        // The house must stay able to act: never drop below M active partners.
        // Signed comparison - ActivePartnerCount()-1 must not underflow (it
        // can't reach here since the partner above is ACTIVE, but keep it safe).
        if (house.ActivePartnerCount() - 1 < (int)house.nThresholdM)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-exit-below-threshold");

        // D13 cap-consistency (the 3.2 promissory note): an exit moves this
        // pledge out of the ACTIVE cap escrow, and escrow leaving is the only
        // channel that can break the mint invariant N <= lambda*E between
        // attestations - so the invariant must hold on the post-exit escrow.
        // (The pledge itself stays TAIL-locked as waterfall backing.)
        {
            const uint32_t nTierIdx = house.nTier <= MAX_HOUSE_TIER ? house.nTier : 0;
            const uint64_t nEscrowAfter = (uint64_t)(house.ActiveEscrow() - partner.amountPledge);
            if (house.nMintedUnits > ((uint64_t)HOUSE_LAMBDA_X10[nTierIdx] * nEscrowAfter) / 10)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-exit-cap");
        }

        // Voluntary (partner's own signature) OR expulsion (M-of-N approvers).
        // Binds the output set so a leaked/dropped exit sig is not replayable.
        const uint256 sighash = HouseExitSigHash(house.houseID, ex.nPartnerIndex, BillHashOutputs(tx));
        bool fAuthorized = false;
        if (!ex.vchPartnerSig.empty()) {
            if (!CPubKey(partner.vchPubKey).Verify(sighash, ex.vchPartnerSig))
                return state.DoS(100, false, REJECT_INVALID, "bad-house-exit-sig");
            fAuthorized = true;
        }
        if (!fAuthorized) {
            if (!VerifyHouseApprovers(house, ex.vApproverIndex, ex.vApproverSig, sighash,
                    house.nThresholdM, state, "bad-house-exit-approver"))
                return false;
            fAuthorized = true;
        }

        // Tail liability: the pledge stays locked for the tail period and
        // leaves the cap escrow immediately (CM-2 active-only counting).
        //
        // NOTE (Phase 3.2 review, deferred to 3.4): EXIT is deliberately NOT
        // gated on outstanding note liabilities the way WINDDOWN is. A partner
        // can exit a house with notes circulating, dropping ActiveEscrow so
        // nMintedUnits may exceed lambda*ActiveEscrow (the mint-cap invariant
        // relaxes) - but the exited pledge stays TAIL-locked as real on-chain
        // backing (reachable by the s7 waterfall) for HOUSE_TAIL_BLOCKS before
        // RECLAIM, and notes are short-dated demand claims, so holders remain
        // backed in the interim. The proportional solvency gate (and gating
        // RECLAIM against the s7 seniority waterfall) lands with 3.4 attestation.
        partner.status = HOUSE_PARTNER_TAIL;
        partner.nTailUnlockHeight = (uint32_t)nHeight + HOUSE_TAIL_BLOCKS;
        houseOut = house;
        return true;
    }

    if (tx.nHouseOp == HOUSE_OP_WINDDOWN) {
        HouseWinddown wd;
        if (!DecodeHousePayload(tx.vchHousePayload, wd))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-winddown-payload");

        CHouse house;
        if (!fnGetHouse(wd.nHouseID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-unknown");
        // Voluntary close from effective Open only (a stressed house resolves
        // through recovery or the waterfall, never a quiet exit)
        if (HouseEffectiveStatus(house, nHeight) != HOUSE_STATUS_OPEN)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-winddown-closed");

        // House on-chain liabilities must be zero (a house cannot abandon
        // outstanding notes/deposits and reclaim its backing). Zero today;
        // GetHouseLiabilities is the hook 3.2 / 5A fill.
        if (GetHouseLiabilities(house) != 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-winddown-liabilities");

        // Binds the output set so a leaked/dropped winddown sig is not replayable.
        const uint256 sighash = HouseWinddownSigHash(house.houseID, BillHashOutputs(tx));
        if (!VerifyHouseApprovers(house, wd.vApproverIndex, wd.vApproverSig, sighash,
                house.nThresholdM, state, "bad-house-winddown-approver"))
            return false;

        // Solo houses have no tail (single issuer, ARCH s3.4): pledge unlocks
        // at this height. Multi-partner pledges take the full tail.
        const bool fSolo = (house.nTier == HOUSE_TIER_BONDED_SOLO ||
                            house.nTier == HOUSE_TIER_ENCUMBERED_SOLO);
        house.status = HOUSE_STATUS_WOUNDDOWN;
        for (HousePartner& p : house.vPartner) {
            if (p.status == HOUSE_PARTNER_ACTIVE) {
                p.status = HOUSE_PARTNER_TAIL;
                p.nTailUnlockHeight = fSolo ? (uint32_t)nHeight : (uint32_t)nHeight + HOUSE_TAIL_BLOCKS;
            }
        }
        houseOut = house;
        return true;
    }

    if (tx.nHouseOp == HOUSE_OP_RECLAIM) {
        HouseReclaim rec;
        if (!DecodeHousePayload(tx.vchHousePayload, rec))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-reclaim-payload");

        CHouse house;
        if (!fnGetHouse(rec.nHouseID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-unknown");
        if (rec.nPartnerIndex >= house.vPartner.size())
            return state.DoS(100, false, REJECT_INVALID, "bad-house-reclaim-partner");
        HousePartner& partner = house.vPartner[rec.nPartnerIndex];

        const char chEff = HouseEffectiveStatus(house, nHeight);

        // D13: no escrow leaves during the stress window - the pledge layer is
        // exactly what the window exists to hold in place. A suspension is the
        // sharpest case of all: the house has stopped paying its holders, so
        // partners certainly may not be walking capital out.
        if (chEff == HOUSE_STATUS_STRESSED || chEff == HOUSE_STATUS_DEFERRED)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-reclaim-stressed");

        if (chEff == HOUSE_STATUS_INSOLVENT) {
            // WHOLE-HOUSE RESIDUAL SETTLE (s7 step 7 / D15). One op, triggered
            // by any unsettled partner, spends EVERY remaining escrow coin and
            // pays each partner their pro-rata residual share at FORCED P2PKH
            // outputs - no per-partner change mechanism, no stranded dust.
            // Valid only after every note unit has been claimed (holders
            // senior forever, D15); tail locks are moot once insolvency has
            // settled (the tail exists to keep pledges reachable for exactly
            // this event).
            if (partner.status == HOUSE_PARTNER_SETTLED)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-settle-already");
            // Both note AND deposit holders are senior to partners (D15): the
            // whole-house residual settle is valid only after every note unit
            // AND every deposit has been claimed.
            if (house.nMintedUnits != 0 || house.nDepositUnits != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-settle-notes-outstanding");
            // A zero-liability house can reach (lazy) insolvency with no note
            // claim ever possible - the settle is then the FIRST waterfall op
            // and materializes the snapshot itself (deadlock escape).
            if (house.status != HOUSE_STATUS_INSOLVENT)
                MaterializeInsolvency(house, nHeight, fnGetProofCoin);

            // Partners take what is left AFTER the senior note par tranche AND the
            // junior deposit tranche (escrow -> deposits -> notes loss order).
            const CAmount amountSenior =
                (CAmount)house.nInsolventUnits + (CAmount)house.nInsolventDepositPrincipal;
            const CAmount amountResidual =
                house.amountInsolventPot > amountSenior
                    ? house.amountInsolventPot - amountSenior : 0;
            if (amountResidual <= 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-settle-no-residual");

            // The trigger partner signs the exact (forced) output set
            const uint256 sighash = HouseReclaimSigHash(house.houseID, rec.nPartnerIndex, BillHashOutputs(tx));
            if (!CPubKey(partner.vchPubKey).Verify(sighash, rec.vchSig))
                return state.DoS(100, false, REJECT_INVALID, "bad-house-reclaim-sig");

            // Every still-live escrow coin (pledges + claim change) must be
            // spent by THIS tx
            std::set<COutPoint> setVin;
            for (const CTxIn& in : tx.vin)
                setVin.insert(in.prevout);
            CAmount amountLive = 0;
            for (const COutPoint& out : HouseEscrowOutpoints(house)) {
                Coin coin;
                if (fnGetProofCoin(out, coin) && !coin.IsSpent() &&
                        coin.fHouseEscrow && coin.nHouseID == house.nHouseID) {
                    if (!setVin.count(out))
                        return state.DoS(100, false, REJECT_INVALID, "bad-house-settle-incomplete");
                    amountLive += coin.out.nValue;
                }
            }

            // Pro-rata shares by pledge over ALL unsettled partners; the last
            // positive share sweeps the leftover (claim-floor dust + any
            // excess of live escrow over the residual), so nothing strands.
            // Weights are the per-partner LIVE escrow frozen at
            // materialization, NOT amountPledge (which RECLAIM never
            // decrements - see HousePartner::amountInsolventPledge).
            CAmount amountPledgeSum = 0;
            for (const HousePartner& p : house.vPartner) {
                if (p.status != HOUSE_PARTNER_SETTLED)
                    amountPledgeSum += p.amountInsolventPledge;
            }
            std::vector<std::pair<size_t, CAmount>> vShare;
            CAmount amountShareSum = 0;
            for (size_t j = 0; j < house.vPartner.size(); j++) {
                if (house.vPartner[j].status == HOUSE_PARTNER_SETTLED)
                    continue;
                const CAmount s = HouseResidualShare(house.vPartner[j].amountInsolventPledge, amountResidual, amountPledgeSum);
                if (s > 0) {
                    vShare.push_back(std::make_pair(j, s));
                    amountShareSum += s;
                }
            }
            if (vShare.empty())
                return state.DoS(100, false, REJECT_INVALID, "bad-house-settle-no-residual");
            // live >= residual >= sum-of-floor-shares, so the sweep is >= 0
            if (amountLive < amountShareSum)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-settle-underfunded");
            vShare.back().second += amountLive - amountShareSum;

            // Forced payout layout: vout[k] pays partner vShare[k] exactly
            if (tx.vout.size() < vShare.size())
                return state.DoS(100, false, REJECT_INVALID, "bad-house-settle-vout");
            for (size_t k = 0; k < vShare.size(); k++) {
                const CScript expected = NoteScriptForPubKey(house.vPartner[vShare[k].first].vchPubKey);
                if (tx.vout[k].scriptPubKey != expected || tx.vout[k].nValue != vShare[k].second)
                    return state.DoS(100, false, REJECT_INVALID, "bad-house-settle-payout");
            }
            // The settle terminates the pot - no output may re-create an
            // escrow-shaped coin (it would enter the UTXO set untagged).
            for (const CTxOut& out : tx.vout) {
                if (IsHouseEscrowScript(out.scriptPubKey))
                    return state.DoS(100, false, REJECT_INVALID, "bad-house-settle-stray-escrow");
            }

            // Everyone settles at once. vOutPledge lists and amountPledge stay
            // untouched (the coins are gone; DisconnectBlock only reverts the
            // statuses, and the generic coin undo restores the coins).
            for (HousePartner& p : house.vPartner) {
                if (p.status != HOUSE_PARTNER_SETTLED)
                    p.status = HOUSE_PARTNER_SETTLED;
            }
            houseOut = house;
            return true;
        }

        // Effective Open or WoundDown: the 3.1 tail-release path
        if (partner.status != HOUSE_PARTNER_TAIL)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-reclaim-not-tail");
        if ((uint32_t)nHeight < partner.nTailUnlockHeight)
            return state.DoS(10, false, REJECT_INVALID, "bad-house-reclaim-early");

        // Whitelist the claiming partner's own pledge outpoints, and index
        // every OTHER partner's outpoints once. Then a single pass over vin:
        // an input matching another partner's outpoint is theft (reject); the
        // scan is O(Sigma-pledges + vin*log P), not O(vin * partners * pledges).
        std::set<COutPoint> setOwn(partner.vOutPledge.begin(), partner.vOutPledge.end());
        std::set<COutPoint> setOther;
        for (size_t j = 0; j < house.vPartner.size(); j++) {
            if (j == rec.nPartnerIndex)
                continue;
            for (const COutPoint& out : house.vPartner[j].vOutPledge)
                setOther.insert(out);
        }
        for (const CTxIn& in : tx.vin) {
            if (setOther.count(in.prevout))
                return state.DoS(100, false, REJECT_INVALID, "bad-house-reclaim-wrong-partner");
        }

        // A tail RECLAIM may spend ONLY the reclaiming partner's own pledge
        // coins. Every other house-escrow coin - the DEFER till (vOutReserveLock)
        // and the brassage/claim change (vOutEscrowChange) - is note-holder money
        // that leaves the pot only via HOUSE_OP_RELEASE or the NOTE_OP_CLAIM
        // waterfall. setOwn was indexed above precisely to enforce this; without
        // the check a former partner past its unlock height could sweep the till
        // and the below-rho brassage spread to itself (both are fHouseEscrow of
        // this house yet in no partner's vOutPledge, so setOther never catches
        // them). Confining the tail path to own-pledge outpoints also keeps the
        // pledge-only reclaim undo byte-exact.
        for (const CTxIn& in : tx.vin) {
            Coin coin;
            if (fnGetProofCoin(in.prevout, coin) && !coin.IsSpent() &&
                coin.fHouseEscrow && !setOwn.count(in.prevout))
                return state.DoS(100, false, REJECT_INVALID, "bad-house-reclaim-not-own-pledge");
        }

        // D13 cap-consistency at effective Open: after this reclaim the LIVE
        // escrow pot must still support the outstanding notes at the tier cap
        // (tail pledges left the cap math at exit but remain waterfall
        // backing - they may not leave while notes would be stranded beyond
        // lambda times the remaining pot). Wound-down houses proved zero
        // liabilities at WINDDOWN and cannot mint, so no check there.
        if (chEff == HOUSE_STATUS_OPEN && house.nMintedUnits != 0) {
            CAmount amountReclaimed = 0;
            for (const CTxIn& in : tx.vin) {
                Coin coin;
                if (fnGetProofCoin(in.prevout, coin) && !coin.IsSpent() && coin.fHouseEscrow)
                    amountReclaimed += coin.out.nValue;
            }
            const CAmount amountLive = HouseLiveEscrowPot(house, fnGetProofCoin);
            const CAmount amountRemaining = amountLive > amountReclaimed ? amountLive - amountReclaimed : 0;
            const uint32_t nTierIdx = house.nTier <= MAX_HOUSE_TIER ? house.nTier : 0;
            const uint64_t capUnits = ((uint64_t)HOUSE_LAMBDA_X10[nTierIdx] * (uint64_t)amountRemaining) / 10;
            if (house.nMintedUnits > capUnits)
                return state.DoS(100, false, REJECT_INVALID, "bad-house-reclaim-cap");
        }

        // The partner signs the exact output set - destination is their choice
        const uint256 sighash = HouseReclaimSigHash(house.houseID, rec.nPartnerIndex, BillHashOutputs(tx));
        if (!CPubKey(partner.vchPubKey).Verify(sighash, rec.vchSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-reclaim-sig");

        // Prune the reclaimed outpoints (those spent by this tx) from the
        // partner record, and canonicalize the survivors' order so the record
        // is byte-identical no matter which path (connect vs disconnect-restore)
        // produced it. amountPledge is deliberately NOT decremented: disconnect
        // runs newest-first, so a RECLAIM undo restores these outpoints BEFORE
        // any EXIT/WINDDOWN undo can reactivate the partner - leaving
        // amountPledge unchanged keeps it consistent with the restored set.
        std::set<COutPoint> setSpent;
        for (const CTxIn& in : tx.vin)
            setSpent.insert(in.prevout);
        std::vector<COutPoint> vRemaining;
        for (const COutPoint& out : partner.vOutPledge) {
            if (!setSpent.count(out))
                vRemaining.push_back(out);
        }
        std::sort(vRemaining.begin(), vRemaining.end());
        partner.vOutPledge = vRemaining;
        houseOut = house;
        return true;
    }

    if (tx.nHouseOp == HOUSE_OP_ATTEST) {
        HouseAttest att;
        if (!DecodeHousePayload(tx.vchHousePayload, att))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-payload");

        CHouse house;
        if (!fnGetHouse(att.nHouseID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-unknown");

        // Attestation is the health-reporting duty of a live house: valid at
        // effective Open, Stressed, or Deferred (the recovery path - and while
        // suspended the market needs the numbers MORE, not less), never once
        // wound down or (lazily) insolvent - effective 'i' must stay absorbing,
        // so nothing may move the derivation inputs after window expiry.
        const char chEffStatus = HouseEffectiveStatus(house, nHeight);
        if (chEffStatus != HOUSE_STATUS_OPEN && chEffStatus != HOUSE_STATUS_STRESSED &&
                chEffStatus != HOUSE_STATUS_DEFERRED)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-closed");

        // Freshness: as-of must be a real past height, within the staleness
        // window, and strictly after the last accepted attestation (monotone -
        // with the priors check below this makes any replay structurally
        // invalid without binding prevouts).
        if (att.nAsOfHeight >= (uint32_t)nHeight)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-future");
        if ((uint32_t)nHeight - att.nAsOfHeight > HOUSE_ATTEST_STALENESS)
            return state.DoS(10, false, REJECT_INVALID, "bad-house-attest-stale");
        if (att.nAsOfHeight <= house.nLastAttestHeight)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-monotone");

        // Undo priors must equal the current DB values: DisconnectBlock
        // restores from the payload alone, byte-exact.
        if (att.nPrevLastAttestHeight != house.nLastAttestHeight ||
                att.nPrevStressSince != house.nStressSinceHeight ||
                att.amountPrevReserves != house.amountLastAttestReserves ||
                att.nPrevDeferInvokedHeight != house.nDeferInvokedHeight ||
                att.nPrevDeferRenewals != house.nDeferRenewals ||
                att.nPrevDeferCumBlocks != house.nDeferCumBlocks ||
                att.nPrevDeferEndedHeight != house.nDeferEndedHeight)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-priors");

        // Per-proof verification against the PARENT-chain UTXO state (order-
        // independent within a block; the ConnectBlock closure recovers coins
        // spent earlier in the same block from the block's own undo data). The
        // proof primitive is shared with NOTE_OP_MINT (R-i7).
        CAmount amountSum = 0;
        if (!VerifyReserveProofs(house.houseID, att.nAsOfHeight, att.vProofs, tx.vin,
                nHeight, fnGetProofCoin, fnGetBlockHash, amountSum, state, "bad-house-attest"))
            return false;
        if (amountSum != att.amountReserves)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-sum");

        // M-of-N approval over the claim + proof set + exact output set
        const uint256 sighash = HouseAttestSigHash(house.houseID, att.nAsOfHeight,
            att.amountReserves, HouseAttestProofSetHash(att.vProofs), BillHashOutputs(tx));
        if (!VerifyHouseApprovers(house, att.vApproverIndex, att.vApproverSig, sighash,
                house.nThresholdM, state, "bad-house-attest-approver"))
            return false;

        // Floor logic (T2 / T4 / in-band, D9) - pure helper, unit-tested.
        // Computed BEFORE nLastAttestHeight moves the cadence clock.
        const uint32_t nNewStress = HouseAttestNewStressOrigin(house, att.amountReserves, nHeight);

        // Option clause (3.5, ARCH s7 step 5): a RECOVERY attestation - one that
        // clears the stress origin, i.e. reaches floor + restoration buffer -
        // LIFTS an invoked deferral. The episode closes and its length is added
        // to the confidence-death ledger. An attestation that does NOT recover
        // leaves the clause running: the window keeps counting down.
        if (house.nDeferInvokedHeight != 0 && nNewStress == 0) {
            house.nDeferCumBlocks += (uint32_t)nHeight > house.nDeferInvokedHeight
                                   ? (uint32_t)nHeight - house.nDeferInvokedHeight : 0;
            house.nDeferInvokedHeight = 0;
            house.nDeferRenewals = 0;
            // DR-2: stamp the episode end. Deferral interest on a demanded note
            // accrues from the date of demand TO THIS HEIGHT, not to the eventual
            // redemption - once the house is paying at par again the forced wait
            // is over and the note stops being an interest-bearing bond.
            house.nDeferEndedHeight = (uint32_t)nHeight;
        }

        house.nStressSinceHeight = nNewStress;
        house.nLastAttestHeight = (uint32_t)nHeight;
        house.amountLastAttestReserves = att.amountReserves;

        // Match-funding rule (Phase 3.8, attestation-checked): the deposits'
        // weighted-average maturity must be >= that of the deposit-funded loan
        // slice, so a house cannot fund long assets with short money. VACUOUS in
        // v1 (the loan slice is 0 - no discounting op exists), so this never
        // fires; it ships now and enforces for real when discounting lands.
        if (!HouseMatchFundingOK(house, nHeight))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-attest-match-funding");

        houseOut = house;
        return true;
    }

    if (tx.nHouseOp == HOUSE_OP_DEFER) {
        HouseDefer def;
        if (!DecodeHousePayload(tx.vchHousePayload, def))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-defer-payload");

        CHouse house;
        if (!fnGetHouse(def.nHouseID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-unknown");

        // The clause is a STRESSED-state tool. Not at Open (nothing to defer -
        // and suspending a healthy house would be pure expropriation), not at
        // Deferred (already invoked - RENEW is the extension path), and never
        // at Insolvent: sim-D1's "insolvency -> resolution, never suspension"
        // is exactly this rejection (D12 - solvency is the effective status).
        if (HouseEffectiveStatus(house, nHeight) != HOUSE_STATUS_STRESSED)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-defer-not-stressed");

        // Confidence death (D13): the guard, not a kill switch. A house that
        // has spent its credibility loses the crisis tool and falls back to the
        // ordinary stress clock - which is what actually kills it.
        if (HouseConfidenceDead(house, nHeight))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-defer-confidence-dead");

        // Undo prior (ATTEST pattern): restoring from the payload alone is then
        // byte-exact, and a replayed invocation always fails.
        if (def.nPrevLastActivation != house.nDeferLastActivation)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-defer-priors");

        // THE TILL GOES INTO THE POT (D11). Suspending is not free: a house that
        // stops paying its holders must put its liquid reserves where those
        // holders can reach them. vout[0] must lock at least the house's ATTESTED
        // reserves into escrow custody, on a FRESH attestation.
        //
        // A house that attested reserves it no longer holds therefore cannot
        // suspend at all - it must first re-attest, truthfully and lower, and
        // lock what it actually has. This is what makes 3.4-D12's "reserves
        // frozen on first detection" - which was pure theatre against plain
        // key-signed coins - into a rule consensus can actually enforce.
        if (nHeight < 0 || (uint32_t)nHeight < house.nLastAttestHeight ||
                (uint32_t)nHeight - house.nLastAttestHeight > HOUSE_ATTEST_CADENCE)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-defer-attest-stale");
        if (tx.vout[0].scriptPubKey != HouseEscrowScript(house.houseID))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-defer-lock-script");
        if (tx.vout[0].nValue < house.amountLastAttestReserves)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-defer-lock-short");
        // Only vout[0] may carry the escrow script (any other would enter the
        // UTXO set untagged and anyone-can-spend).
        for (size_t o = 1; o < tx.vout.size(); o++) {
            if (tx.vout[o].scriptPubKey == HouseEscrowScript(house.houseID))
                return state.DoS(100, false, REJECT_INVALID, "bad-house-defer-stray-escrow");
        }

        const uint256 sighash = HouseDeferSigHash(house.houseID, def.nPrevLastActivation, BillHashOutputs(tx));
        if (!VerifyHouseApprovers(house, def.vApproverIndex, def.vApproverSig, sighash,
                house.nThresholdM, state, "bad-house-defer-approver"))
            return false;

        house.nDeferInvokedHeight = (uint32_t)nHeight;
        house.nDeferRenewals = 0;
        house.nDeferActivations++;
        house.nDeferLastActivation = (uint32_t)nHeight;
        house.vOutReserveLock.push_back(COutPoint(tx.GetHash(), 0));
        std::sort(house.vOutReserveLock.begin(), house.vOutReserveLock.end());
        houseOut = house;
        return true;
    }

    if (tx.nHouseOp == HOUSE_OP_RELEASE) {
        HouseRelease rel;
        if (!DecodeHousePayload(tx.vchHousePayload, rel))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-release-payload");

        CHouse house;
        if (!fnGetHouse(rel.nHouseID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-unknown");

        // The till comes back only once the clause has been LIFTED - i.e. the
        // house is effectively Open again and can pay its queue. While Stressed,
        // Deferred or Insolvent it stays where the holders can reach it.
        if (HouseEffectiveStatus(house, nHeight) != HOUSE_STATUS_OPEN)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-release-not-open");
        if (house.vOutReserveLock.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-house-release-nothing-locked");

        // Spends ONLY reserve-lock coins (never a partner pledge, never the
        // brassage/claim escrow change - those belong to the pot for good).
        std::set<COutPoint> setLock(house.vOutReserveLock.begin(), house.vOutReserveLock.end());
        for (const CTxIn& in : tx.vin) {
            Coin coin;
            if (fnGetProofCoin(in.prevout, coin) && !coin.IsSpent() && coin.fHouseEscrow &&
                    !setLock.count(in.prevout))
                return state.DoS(100, false, REJECT_INVALID, "bad-house-release-wrong-escrow");
        }
        // No output may re-create an escrow coin (it would be untracked).
        for (const CTxOut& out : tx.vout) {
            if (IsHouseEscrowScript(out.scriptPubKey))
                return state.DoS(100, false, REJECT_INVALID, "bad-house-release-stray-escrow");
        }

        const uint256 sighash = HouseReleaseSigHash(house.houseID, NoteHashPrevouts(tx), BillHashOutputs(tx));
        if (!VerifyHouseApprovers(house, rel.vApproverIndex, rel.vApproverSig, sighash,
                house.nThresholdM, state, "bad-house-release-approver"))
            return false;

        // Drop the outpoints this tx actually spent (partial release is fine).
        std::set<COutPoint> setSpent;
        for (const CTxIn& in : tx.vin)
            setSpent.insert(in.prevout);
        std::vector<COutPoint> vRemaining;
        for (const COutPoint& out : house.vOutReserveLock) {
            if (!setSpent.count(out))
                vRemaining.push_back(out);
        }
        std::sort(vRemaining.begin(), vRemaining.end());
        house.vOutReserveLock = vRemaining;
        houseOut = house;
        return true;
    }

    if (tx.nHouseOp == HOUSE_OP_RENEW) {
        HouseRenew ren;
        if (!DecodeHousePayload(tx.vchHousePayload, ren))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-renew-payload");

        CHouse house;
        if (!fnGetHouse(ren.nHouseID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-unknown");

        // Only while the clause is actually running (a renewal after expiry
        // would be a resurrection - the house is insolvent by then).
        if (HouseEffectiveStatus(house, nHeight) != HOUSE_STATUS_DEFERRED)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-renew-not-deferred");
        if (house.nDeferRenewals >= HOUSE_DEFER_MAX_RENEWALS)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-renew-exhausted");
        // A renewal that would carry the house past the cumulative-suspension
        // cap is refused up front rather than granted and then voided.
        if (house.DeferSuspendedBlocks(nHeight) >= HOUSE_CD_MAX_SUSPENDED)
            return state.DoS(100, false, REJECT_INVALID, "bad-house-renew-confidence-dead");

        const uint256 sighash = HouseRenewSigHash(house.houseID, house.nDeferRenewals, NoteHashPrevouts(tx), BillHashOutputs(tx));
        if (!VerifyHouseApprovers(house, ren.vApproverIndex, ren.vApproverSig, sighash,
                house.nThresholdM, state, "bad-house-renew-approver"))
            return false;

        house.nDeferRenewals++;
        houseOut = house;
        return true;
    }

    return state.DoS(100, false, REJECT_INVALID, "bad-house-op");
}

/** Contextual validation of a note operation (Phase 3.2). tx_verify has already
 * done the structure + unit accounting (conservation, single-house inputs,
 * holder-script match); this does the ECDSA authorization and the house-state
 * effects (cap / status / nMintedUnits). nNoteUnitsIn is the units burned by a
 * REDEEM (0 otherwise). On success, for MINT/REDEEM houseOut carries the house
 * with its updated nMintedUnits and fHouseChanged is true (the caller stages it
 * under the one-op-per-house-per-block rule, like a governance op); TRANSFER
 * changes no house state (fHouseChanged=false). */
bool CheckNoteOperation(const CTransaction& tx, CValidationState& state, int nHeight, uint64_t nNoteUnitsIn,
                        const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                        const std::function<bool(const COutPoint&, Coin&)>& fnGetCoin,
                        const std::function<bool(const COutPoint&, Coin&)>& fnGetProofCoin,
                        const std::function<bool(uint32_t, uint256&)>& fnGetBlockHash,
                        CHouse& houseOut, bool& fHouseChanged)
{
    fHouseChanged = false;
    const uint256 hashOutputs = BillHashOutputs(tx);

    if (tx.nNoteOp == NOTE_OP_MINT) {
        NoteMint mint;
        if (!DecodeNotePayload(tx.vchNotePayload, mint))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-payload");

        uint64_t total = 0;
        if (!SumNoteUnits(mint.vUnits, total))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-units");

        CHouse house;
        if (!fnGetHouse(mint.nHouseID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-unknown-house");
        // Mint only while EFFECTIVELY Open (3.4): a stressed house - ratio
        // breach or missed attestation cadence, both possibly derived rather
        // than stored - cannot issue; only redemption and recovery capital.
        if (HouseEffectiveStatus(house, nHeight) != HOUSE_STATUS_OPEN)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-house-not-open");

        // CAPITAL cap (CM-2): N + total + D <= lambda * E, with lambda =
        // HOUSE_LAMBDA_X10/10 and E = active escrow (sats). D = outstanding term
        // deposits (Phase 3.8): notes and deposits SHARE the one lambda ceiling,
        // so live deposits shrink mint headroom (and vice-versa - ORIGINATE reads
        // live nMintedUnits). All terms are money-range (<= MAX_MONEY), so
        // N + D + total <= 3*MAX_MONEY fits u64 and lambdaX10*E <= 30*2.1e15 fits.
        if (house.nMintedUnits > (uint64_t)MAX_MONEY - total ||
                house.nMintedUnits + total > (uint64_t)MAX_MONEY - house.nDepositUnits ||
                house.nMintedUnits + total + house.nDepositUnits > HouseCapitalCapUnits(house))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-over-cap");

        // RESERVE cap (Phase 3.5 D2 - "the rho-at-mint gate"): issuance is ALSO
        // bounded by the house's ATTESTED liquid till - N + mint <= R / rho.
        //
        // CM-2 always specified the PAIR (the lambda capital cap AND the rho
        // liquid-reserve floor). 3.4 shipped lambda as a hard gate at mint but
        // rho only as a RETROACTIVE check at attestation - so a house could top
        // up escrow and mint lambda*dE new notes holding ZERO reserves, in one
        // transaction, walking itself through the floor and only being caught a
        // cadence later. The validated sim's bank could never do that (its mint
        // room was rho-gated), and that divergence - not brassage - is what kept
        // it alive: base-native, rho-gated, it survives every modelled panic
        // with no fee at all; lambda-only, it dies at all of them.
        //
        // A recent published attestation is still required (cadence +
        // transparency): amountLastAttestReserves is the house's PUBLIC reserve
        // figure, and a never-attested house has R = 0 and cannot mint.
        if (nHeight < 0 || (uint32_t)nHeight < house.nLastAttestHeight ||
                (uint32_t)nHeight - house.nLastAttestHeight > HOUSE_ATTEST_CADENCE)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-attest-stale");
        // R-i7 (DR-1): the published figure must ALSO be PROVEN LIVE in this very
        // mint. The pre-R-i7 gate trusted the snapshot alone, so a house could
        // attest with flash reserves, spend them the next block, and mint the
        // full cap holding zero liquid sats until the next cadence. The mint now
        // carries the ATTEST proof primitive (declared outpoints + per-coin
        // recency sigs), verified against the UTXO set at mint height, and the
        // BINDING reserve is min(published snapshot, freshly-proven live): a house
        // that attested reserves it has since spent cannot mint against the stale
        // published number. No oracle - the reserve coins are on-chain base value.
        if (mint.nAsOfHeight >= (uint32_t)nHeight)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-reserve-future");
        if ((uint32_t)nHeight - mint.nAsOfHeight > HOUSE_ATTEST_STALENESS)
            return state.DoS(10, false, REJECT_INVALID, "bad-note-mint-reserve-stale");
        // The reserve proof resolves against PARENT-CHAIN state (fnGetProofCoin),
        // NOT the note-input view (fnGetCoin): exactly as HOUSE_OP_ATTEST does. A
        // mempool or same-block spend of a proven reserve coin (which the mint
        // does NOT spend) must not invalidate the mint - both can ride the same
        // block. Otherwise a non-input coin drives mint validity, which the
        // mempool cannot conflict-track, and a stale mint would brick the next
        // template (CreateNewBlock throws on TestBlockValidity) - the 3.4 lazy-
        // invalidation trap, re-opened. R-i7 review finding.
        CAmount amountLiveReserves = 0;
        if (!VerifyReserveProofs(house.houseID, mint.nAsOfHeight, mint.vReserveProofs, tx.vin,
                nHeight, fnGetProofCoin, fnGetBlockHash, amountLiveReserves, state, "bad-note-mint-reserve"))
            return false;
        const CAmount amountEffReserves = std::min(house.amountLastAttestReserves, amountLiveReserves);
        const uint64_t reserveCap = ((uint64_t)amountEffReserves * 100) / HOUSE_RESERVE_FLOOR_PCT;
        if (house.nMintedUnits + total > reserveCap)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-under-reserved");

        // House M-of-N authorizes the exact issuance (house_id + vUnits +
        // inputs + outputs). Binding hashPrevouts makes the approver signatures
        // tx-unique so a confirmed mint cannot be replayed with fresh funding
        // to re-issue the same notes without new consent.
        if (!VerifyHouseApprovers(house, mint.vApproverIndex, mint.vApproverSig,
                NoteMintSigHash(mint.nHouseID, mint.vUnits, NoteHashPrevouts(tx), hashOutputs),
                house.nThresholdM, state, "bad-note-mint-approver"))
            return false;

        house.nMintedUnits += total;
        houseOut = house;
        fHouseChanged = true;
        return true;
    }

    if (tx.nNoteOp == NOTE_OP_TRANSFER) {
        NoteTransfer xfer;
        if (!DecodeNotePayload(tx.vchNotePayload, xfer))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-transfer-payload");

        // The sender authorizes the exact split + destinations (this is what
        // binds the trailer payload the legacy input sighash does not cover).
        if (!CPubKey(xfer.vchSenderPubKey).Verify(
                NoteTransferSigHash(xfer.nHouseID, xfer.vUnits, hashOutputs), xfer.vchSenderSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-transfer-sig");
        return true; // no house-state change
    }

    if (tx.nNoteOp == NOTE_OP_REDEEM) {
        NoteRedeem redeem;
        if (!DecodeNotePayload(tx.vchNotePayload, redeem))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-payload");

        CHouse house;
        if (!fnGetHouse(redeem.nHouseID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-unknown-house");
        // Redemption stays open AT PAR through Stressed to the last day (D6 -
        // the record's invariant: the window never quietly closes). Blocked at
        // effective Insolvent (the pro-rata waterfall replaces it) and after
        // wind-down.
        //
        // At DEFERRED the option clause has been invoked: par redemption stops
        // and the holder QUEUES instead, accruing interest from the date of
        // demand (R-i3 lands NOTE_OP_DEMAND and the paid-out-with-interest
        // path; until then a suspension simply halts redemption, which is the
        // conservative half of the mechanic).
        {
            const char chEff = HouseEffectiveStatus(house, nHeight);
            if (chEff == HOUSE_STATUS_DEFERRED)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-deferred");
            if (chEff != HOUSE_STATUS_OPEN && chEff != HOUSE_STATUS_STRESSED)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-house-closed");
        }

        // The holder authorizes burning U units AND (by binding hashOutputs)
        // the exact payout - so they never surrender notes without the payment
        // they signed for.
        if (!CPubKey(redeem.vchHolderPubKey).Verify(
                NoteRedeemSigHash(redeem.nHouseID, nNoteUnitsIn, hashOutputs), redeem.vchHolderSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-sig");

        // DEFERRAL INTEREST (3.5 D6). Redeeming notes that were DEMANDED during
        // a suspension pays principal + 5%/yr accrued from the DATE OF DEMAND -
        // and unlike ordinary redemption (notes-D5: the holder signs whatever
        // payout they accept), this one has a consensus FLOOR. The compensation
        // for a forced wait must not be renegotiable under duress: a holder who
        // has been queued for months is exactly the party with no bargaining
        // power left.
        {
            uint32_t nDemandHeight = 0;
            for (const CTxIn& in : tx.vin) {
                Coin coin;
                if (fnGetCoin(in.prevout, coin) && coin.fNote && coin.nDemandHeight != 0) {
                    nDemandHeight = coin.nDemandHeight;   // tx_verify: uniform across inputs
                    break;
                }
            }
            if (nDemandHeight != 0) {
                // DR-2: the interest window is capped at the END of the deferral
                // episode (the recovery attestation's height). The clause
                // compensates a FORCED wait; once the house redeems at par again
                // the holder is waiting by choice, and without the cap the
                // permanent nDemandHeight coin tag turned "demand once, hold" into
                // a perpetual 5%/yr bond. A note demanded in an earlier episode
                // and redeemed after a later recovery caps at the LATER end
                // (bounded over-pay - accepted; the alternative is per-note
                // episode tracking). If no recovery post-dates the demand the
                // house is still suspended (redeem is blocked at Deferred), or
                // the record pre-dates DR-2 (v5 migration: 0 = uncapped until
                // the next recovery stamps it).
                // INCLUSIVE on the demand side (review finding): a demand that
                // connects in the SAME block as the recovery attestation gets
                // D == E - its forced wait ended the block it began, so the
                // window is zero, NOT uncapped.
                uint32_t nEndHeight = (uint32_t)nHeight;
                if (house.nDeferEndedHeight >= nDemandHeight &&
                        house.nDeferEndedHeight < nEndHeight)
                    nEndHeight = house.nDeferEndedHeight;
                const uint32_t nBlocks = nEndHeight > nDemandHeight
                                       ? nEndHeight - nDemandHeight : 0;
                const CAmount amountInterest = NoteDeferralInterest(nNoteUnitsIn, nBlocks);
                const CAmount amountDue = (CAmount)nNoteUnitsIn + amountInterest;
                // Sum everything paid to the holder's own script.
                const CScript scriptHolder = NoteScriptForPubKey(redeem.vchHolderPubKey);
                CAmount amountPaid = 0;
                for (const CTxOut& out : tx.vout) {
                    if (out.scriptPubKey == scriptHolder)
                        amountPaid += out.nValue;
                }
                if (amountPaid < amountDue)
                    return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-interest-short");
            }
        }

        // DYNAMIC BRASSAGE (3.5 D1/D10). A redemption while the house's attested
        // ratio is below rho pays a spread INTO THE ESCROW POT - so the holder
        // who runs compensates the holders who stay, instead of stranding them.
        // Par redemption on a fractional reserve always lowers the ratio, which
        // is what makes the exit a race; this prices it.
        //
        // DR-2: demanded notes are NOT exempt. The old exemption keyed on the
        // permanent nDemandHeight coin tag, making a once-demanded note
        // brassage-free forever. It also never did the job it was meant for:
        // the queue is paid out AFTER recovery, and a recovery attestation is
        // by definition at floor+buffer, so the attested ratio is back above
        // rho and the spread is zero for everyone at that point. The only time
        // a demanded note could owe a spread is a NEW below-floor stress that
        // post-dates the recovery - a new race the exiting holder should price
        // like every other holder. (The spec alternative - gate on effective
        // Deferred - is equivalent: redemption is blocked at Deferred above,
        // so the gate can never pass here.)
        {
            const uint32_t nBps = HouseBrassageBps(house);
            const CAmount amountSpread = HouseBrassageAmount(nNoteUnitsIn, nBps);

            const CScript scriptEscrow = HouseEscrowScript(house.houseID);
            if (amountSpread > 0) {
                if (!redeem.fBrassage)
                    return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-brassage-missing");
                if (tx.vout[1].scriptPubKey != scriptEscrow)
                    return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-brassage-script");
                if (tx.vout[1].nValue < amountSpread)
                    return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-brassage-short");
            } else if (redeem.fBrassage) {
                // No spread owed: an escrow-script output here would enter the
                // UTXO set with no consensus tracking behind it.
                return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-brassage-unexpected");
            }
            // No OTHER output may carry the escrow script (only vout[1] is
            // re-tagged, so any other would be an untagged anyone-can-spend coin).
            for (size_t o = 0; o < tx.vout.size(); o++) {
                if ((o != 1 || !redeem.fBrassage) && tx.vout[o].scriptPubKey == scriptEscrow)
                    return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-stray-escrow");
            }
            // The spread joins the pot, so its outpoint must be enumerable.
            if (redeem.fBrassage) {
                house.vOutEscrowChange.push_back(COutPoint(tx.GetHash(), 1));
                std::sort(house.vOutEscrowChange.begin(), house.vOutEscrowChange.end());
            }
        }

        // Retire the burned units from the outstanding total (cannot underflow -
        // the units exist as spent note coins the house minted).
        if (house.nMintedUnits < nNoteUnitsIn)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-underflow");
        house.nMintedUnits -= nNoteUnitsIn;
        houseOut = house;
        fHouseChanged = true;
        return true;
    }

    if (tx.nNoteOp == NOTE_OP_DEMAND) {
        NoteDemand dem;
        if (!DecodeNotePayload(tx.vchNotePayload, dem))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-payload");

        CHouse house;
        if (!fnGetHouse(dem.nHouseID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-unknown-house");

        // A demand is only meaningful while the clause is running: at Open or
        // Stressed the holder simply REDEEMS at par (and lodging a demand there
        // would be a way to start an interest clock the house never agreed to),
        // and at Insolvent the pro-rata waterfall replaces redemption.
        if (HouseEffectiveStatus(house, nHeight) != HOUSE_STATUS_DEFERRED)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-not-deferred");

        // The holder authorizes the exact re-issue (units + outputs).
        if (!CPubKey(dem.vchHolderPubKey).Verify(
                NoteDemandSigHash(dem.nHouseID, dem.vUnits, hashOutputs), dem.vchHolderSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-sig");

        // No house state changes: the units stay outstanding (a demanded note
        // is still a liability), so a demand does NOT take the one-op-per-house
        // slot and any number of holders can queue in the same block.
        return true;
    }

    if (tx.nNoteOp == NOTE_OP_CLAIM) {
        NoteClaim claim;
        if (!DecodeNotePayload(tx.vchNotePayload, claim))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-payload");

        CHouse house;
        if (!fnGetHouse(claim.nHouseID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-unknown-house");
        // The waterfall replaces redemption ONLY at insolvency (usually
        // derived: window expiry is lazy - the claim itself materializes it).
        if (HouseEffectiveStatus(house, nHeight) != HOUSE_STATUS_INSOLVENT)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-not-insolvent");

        // The holder authorizes burning U units AND (hashOutputs) the exact
        // payout + escrow change they computed.
        if (!CPubKey(claim.vchHolderPubKey).Verify(
                NoteClaimSigHash(claim.nHouseID, nNoteUnitsIn, hashOutputs), claim.vchHolderSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-sig");

        // First waterfall op materializes: status char + the pro-rata
        // denominator snapshot (pot = LIVE escrow coins, units = outstanding).
        if (house.status != HOUSE_STATUS_INSOLVENT)
            MaterializeInsolvency(house, nHeight, fnGetCoin);

        // Escrow accounting: what this tx takes out of the pot.
        CAmount amountEscrowIn = 0;
        for (const CTxIn& in : tx.vin) {
            Coin coin;
            if (fnGetCoin(in.prevout, coin) && !coin.IsSpent() && coin.fHouseEscrow)
                amountEscrowIn += coin.out.nValue;
        }
        CAmount amountEscrowChange = 0;
        if (claim.fEscrowChange) {
            // Shape guaranteed vout[1] exists; it must carry the canonical
            // escrow script so AddCoins' payload-driven re-tag matches it.
            if (tx.vout[1].scriptPubKey != HouseEscrowScript(house.houseID))
                return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-escrow-script");
            amountEscrowChange = tx.vout[1].nValue;
        }
        // No other output may carry the escrow script (tag confusion: only
        // vout[1] is re-tagged, so any other escrow-script output would enter
        // the UTXO set as an UNTAGGED anyone-can-spend coin).
        for (size_t o = 0; o < tx.vout.size(); o++) {
            if ((o != 1 || !claim.fEscrowChange) &&
                    tx.vout[o].scriptPubKey == HouseEscrowScript(house.houseID))
                return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-stray-escrow");
        }
        if (amountEscrowChange > amountEscrowIn)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-escrow-inflation");

        // Pro-rata bound (D5): the fixed snapshot denominator makes claims
        // order-independent - no front-running in the terminal state.
        const CAmount amountEntitlement =
            NoteClaimEntitlement(nNoteUnitsIn, house.amountInsolventPot, house.nInsolventUnits);
        if (amountEscrowIn - amountEscrowChange > amountEntitlement)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-over-entitlement");

        if (house.nMintedUnits < nNoteUnitsIn)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-underflow");
        house.nMintedUnits -= nNoteUnitsIn;
        // Track the change outpoint - the pledge lists keep the (now spent)
        // originals, so later claims/settles enumerate the pot through this.
        // Drop any change coin THIS claim consumed first, so the list holds
        // only LIVE change and cannot grow without bound (3.4 review); keep
        // it sorted so reorged and fresh-synced records stay byte-identical.
        {
            std::set<COutPoint> setSpentIn;
            for (const CTxIn& in : tx.vin)
                setSpentIn.insert(in.prevout);
            std::vector<COutPoint> vKeep;
            for (const COutPoint& out : house.vOutEscrowChange) {
                if (!setSpentIn.count(out))
                    vKeep.push_back(out);
            }
            if (claim.fEscrowChange)
                vKeep.push_back(COutPoint(tx.GetHash(), 1));
            std::sort(vKeep.begin(), vKeep.end());
            house.vOutEscrowChange = vKeep;
        }
        houseOut = house;
        fHouseChanged = true;
        return true;
    }

    return state.DoS(100, false, REJECT_INVALID, "bad-note-op");
}

/** Contextual validation of a term-deposit operation (Phase 3.8). tx_verify has
 * done the structure + receipt-input guards; this does the ECDSA authorization
 * and the house-state effects. For ORIGINATE (and later WITHDRAW/CLAIM) houseOut
 * carries the house with its updated deposit accounting and fHouseChanged is true
 * (the caller stages it under the one-house-state-change-per-house-per-block
 * rule); TRANSFER changes no house state (fHouseChanged=false). */
bool CheckDepositOperation(const CTransaction& tx, CValidationState& state, int nHeight,
                           const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                           const std::function<bool(const COutPoint&, Coin&)>& fnGetCoin,
                           CHouse& houseOut, bool& fHouseChanged)
{
    fHouseChanged = false;
    const uint256 hashOutputs = BillHashOutputs(tx);

    if (tx.nDepositOp == DEPOSIT_OP_ORIGINATE) {
        DepositOriginate org;
        if (!DecodeDepositPayload(tx.vchDepositPayload, org))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-originate-payload");
        uint64_t total = 0;
        if (!SumDepositPrincipal(org.vPrincipal, total))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-originate-principal");

        CHouse house;
        if (!fnGetHouse(org.nHouseID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-unknown-house");
        // Originate only while effectively Open: a stressed / deferred / insolvent
        // house cannot take on new term liabilities (it is already in trouble).
        if (HouseEffectiveStatus(house, nHeight) != HOUSE_STATUS_OPEN)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-originate-house-not-open");

        // Per-receipt maturity: strictly in the future (a term is > 0 blocks) and
        // within the bound. Accumulate the 128-bit weighted maturity in one pass.
        unsigned __int128 wtDelta = 0;
        for (size_t i = 0; i < org.vMaturityHeight.size(); i++) {
            const uint32_t m = org.vMaturityHeight[i];
            if (nHeight < 0 || m <= (uint32_t)nHeight)
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-originate-not-future");
            if (m - (uint32_t)nHeight > MAX_DEPOSIT_TERM_BLOCKS)
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-originate-term-too-long");
            wtDelta += (unsigned __int128)org.vPrincipal[i] * (unsigned __int128)m;
        }

        // CM-2 CAPITAL cap, SHARED with notes: N + D + total <= lambda * E. Reads
        // LIVE nMintedUnits (notes and deposits share the one leverage ceiling).
        // Deposits are OUTSIDE rho - NO reserve proof, NO rho gate: a term-locked,
        // non-redeemable claim cannot run, so it is not backed against liquidity.
        if (house.nDepositUnits > (uint64_t)MAX_MONEY - total ||
                house.nMintedUnits > (uint64_t)MAX_MONEY - (house.nDepositUnits + total) ||
                house.nMintedUnits + house.nDepositUnits + total > HouseCapitalCapUnits(house))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-originate-over-cap");

        // House M-of-N authorizes the exact batch (house_id + terms + inputs +
        // outputs). Binding DepositHashPrevouts makes a confirmed origination's
        // approver sigs non-replayable with fresh funding (the notes-MINT lesson).
        if (!VerifyHouseApprovers(house, org.vApproverIndex, org.vApproverSig,
                DepositOriginateSigHash(org.nHouseID, org.vPrincipal, org.vRateBps, org.vMaturityHeight,
                    DepositHashPrevouts(tx), hashOutputs),
                house.nThresholdM, state, "bad-deposit-originate-approver"))
            return false;

        house.nDepositUnits += total;
        house.SetDepositWtMaturity(house.DepositWtMaturity() + wtDelta);
        houseOut = house;
        fHouseChanged = true;
        return true;
    }

    if (tx.nDepositOp == DEPOSIT_OP_TRANSFER) {
        DepositTransfer x;
        if (!DecodeDepositPayload(tx.vchDepositPayload, x))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-transfer-payload");
        // The ONE receipt input's coin-tag terms MUST equal the payload byte-exact
        // (no re-pricing - the terms are immutable). tx_verify already enforced
        // exactly one receipt input, scripted to the declared sender, and a single
        // receipt output; AddCoins tags that output from this payload, so a lie
        // here would mint different terms out of thin air.
        Coin receipt;
        bool fFound = false;
        for (const CTxIn& in : tx.vin) {
            Coin c;
            if (fnGetCoin(in.prevout, c) && c.fDeposit) { receipt = c; fFound = true; break; }
        }
        if (!fFound)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-transfer-no-receipt");
        if (receipt.nHouseID != x.nHouseID || receipt.nDepositPrincipal != x.nPrincipal ||
                receipt.nDepositRateBps != x.nRateBps ||
                receipt.nDepositMaturityHeight != x.nMaturityHeight ||
                receipt.nDepositOriginationHeight != x.nOriginationHeight)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-transfer-terms-mismatch");
        // The sender authorizes the exact terms + destination (hashOutputs). This
        // binds the trailer payload the legacy input sighash does not cover.
        if (!CPubKey(x.vchSenderPubKey).Verify(
                DepositTransferSigHash(x.nHouseID, x.nPrincipal, x.nRateBps, x.nMaturityHeight,
                    x.nOriginationHeight, hashOutputs),
                x.vchSenderSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-transfer-sig");
        return true; // whole-receipt reassignment - no house-state change
    }

    if (tx.nDepositOp == DEPOSIT_OP_WITHDRAW) {
        DepositWithdraw wd;
        if (!DecodeDepositPayload(tx.vchDepositPayload, wd))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-withdraw-payload");
        CHouse house;
        if (!fnGetHouse(wd.nHouseID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-unknown-house");
        // Withdrawable ONLY while effectively Open. This is the subordination: a
        // matured deposit "queues behind notes" - while the house is Stressed /
        // Deferred / Insolvent it cannot be withdrawn (notes keep par-redemption
        // through Stressed), and it simply keeps accruing at its own rate until
        // recovery (or drops into CLAIM at insolvency).
        if (HouseEffectiveStatus(house, nHeight) != HOUSE_STATUS_OPEN)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-withdraw-house-not-open");

        // The one burned receipt carries the terms (tx_verify enforced exactly one
        // receipt input, scripted to the declared holder).
        Coin receipt;
        bool fFound = false;
        for (const CTxIn& in : tx.vin) {
            Coin c;
            if (fnGetCoin(in.prevout, c) && c.fDeposit) { receipt = c; fFound = true; break; }
        }
        if (!fFound)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-withdraw-no-receipt");
        // Term-locked: no early withdrawal from the house (early liquidity is a
        // market sale of the receipt - TRANSFER).
        if (nHeight < 0 || (uint32_t)nHeight < receipt.nDepositMaturityHeight)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-not-matured");

        // CONSENSUS interest FLOOR (unlike note par-redemption's free-choice
        // payout): the holder must be paid >= principal + accrued, at the RECEIPT'S
        // OWN rate on ONE CONTINUOUS clock from origination (a deposit paid late
        // simply earns more). A matured saver has no leverage and must not be able
        // to be shortchanged of accrued.
        const uint32_t nBlocks = (uint32_t)nHeight > receipt.nDepositOriginationHeight
                               ? (uint32_t)nHeight - receipt.nDepositOriginationHeight : 0;
        const CAmount amountInterest = DepositMaturityInterest(receipt.nDepositPrincipal, nBlocks, receipt.nDepositRateBps);
        const CAmount amountDue = (CAmount)receipt.nDepositPrincipal + amountInterest;
        const CScript scriptHolder = DepositScriptForPubKey(wd.vchHolderPubKey);
        CAmount amountPaid = 0;
        for (const CTxOut& out : tx.vout) {
            if (out.scriptPubKey == scriptHolder)
                amountPaid += out.nValue;
        }
        if (amountPaid < amountDue)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-withdraw-underpaid");

        // The holder authorizes the exact payout (binds hashOutputs) AND supplies
        // the P2PKH scriptSig on the burned receipt (SIGHASH_ALL) - both bind the
        // output set, so they never surrender the receipt without the payout.
        if (!CPubKey(wd.vchHolderPubKey).Verify(
                DepositWithdrawSigHash(wd.nHouseID, receipt.nDepositPrincipal, receipt.nDepositMaturityHeight,
                    receipt.nDepositOriginationHeight, hashOutputs),
                wd.vchHolderSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-withdraw-sig");

        if (house.nDepositUnits < receipt.nDepositPrincipal)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-withdraw-accounting");
        house.nDepositUnits -= receipt.nDepositPrincipal;
        house.SetDepositWtMaturity(house.DepositWtMaturity() -
            (unsigned __int128)receipt.nDepositPrincipal * (unsigned __int128)receipt.nDepositMaturityHeight);
        houseOut = house;
        fHouseChanged = true;
        return true;
    }

    if (tx.nDepositOp == DEPOSIT_OP_CLAIM) {
        DepositClaim clm;
        if (!DecodeDepositPayload(tx.vchDepositPayload, clm))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-claim-payload");
        CHouse house;
        if (!fnGetHouse(clm.nHouseID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-unknown-house");
        // The subordinated waterfall replaces withdrawal ONLY at insolvency
        // (usually derived: window/deferral expiry is lazy - a claim itself
        // materializes it).
        if (HouseEffectiveStatus(house, nHeight) != HOUSE_STATUS_INSOLVENT)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-claim-not-insolvent");

        // The one burned receipt's principal (tx_verify enforced exactly one
        // receipt input, scripted to the declared holder).
        Coin receipt;
        bool fFound = false;
        for (const CTxIn& in : tx.vin) {
            Coin c;
            if (fnGetCoin(in.prevout, c) && c.fDeposit) { receipt = c; fFound = true; break; }
        }
        if (!fFound)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-claim-no-receipt");

        // The holder authorizes burning the receipt AND (hashOutputs) the exact
        // payout + escrow change.
        if (!CPubKey(clm.vchHolderPubKey).Verify(
                DepositClaimSigHash(clm.nHouseID, receipt.nDepositPrincipal, hashOutputs), clm.vchHolderSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-claim-sig");

        // First waterfall op materializes: freezes pot, the note snapshot, AND the
        // deposit snapshot.
        if (house.status != HOUSE_STATUS_INSOLVENT)
            MaterializeInsolvency(house, nHeight, fnGetCoin);

        // Escrow accounting: what this tx takes out of the pot (same shape as the
        // note CLAIM; only the tranche denominator differs).
        CAmount amountEscrowIn = 0;
        for (const CTxIn& in : tx.vin) {
            Coin coin;
            if (fnGetCoin(in.prevout, coin) && !coin.IsSpent() && coin.fHouseEscrow)
                amountEscrowIn += coin.out.nValue;
        }
        CAmount amountEscrowChange = 0;
        if (clm.fEscrowChange) {
            if (tx.vout.size() < 2 || tx.vout[1].scriptPubKey != HouseEscrowScript(house.houseID))
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-claim-escrow-script");
            amountEscrowChange = tx.vout[1].nValue;
        }
        for (size_t o = 0; o < tx.vout.size(); o++) {
            if ((o != 1 || !clm.fEscrowChange) &&
                    tx.vout[o].scriptPubKey == HouseEscrowScript(house.houseID))
                return state.DoS(100, false, REJECT_INVALID, "bad-deposit-claim-stray-escrow");
        }
        if (amountEscrowChange > amountEscrowIn)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-claim-escrow-inflation");

        // JUNIOR deposit tranche = what the pot has left AFTER notes take their par
        // (nInsolventUnits). Capped at principal (accrued interest does not survive
        // materialization, symmetric with notes). Both operands are the FROZEN
        // snapshot, so claims are order-independent and provably cannot reach the
        // senior note par tranche: sum(deposit takes) <= depositPot = pot -
        // nInsolventUnits, so >= nInsolventUnits always remains for the notes.
        const CAmount amountDepositPot =
            house.amountInsolventPot > (CAmount)house.nInsolventUnits
                ? house.amountInsolventPot - (CAmount)house.nInsolventUnits : 0;
        const CAmount amountEntitlement =
            DepositClaimEntitlement(receipt.nDepositPrincipal, amountDepositPot, house.nInsolventDepositPrincipal);
        if (amountEscrowIn - amountEscrowChange > amountEntitlement)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-claim-over-entitlement");

        if (house.nDepositUnits < receipt.nDepositPrincipal)
            return state.DoS(100, false, REJECT_INVALID, "bad-deposit-claim-underflow");
        house.nDepositUnits -= receipt.nDepositPrincipal;
        house.SetDepositWtMaturity(house.DepositWtMaturity() -
            (unsigned __int128)receipt.nDepositPrincipal * (unsigned __int128)receipt.nDepositMaturityHeight);
        // Track the escrow-change outpoint (identical bookkeeping to the note
        // CLAIM): drop any change this claim consumed, add the change it created,
        // keep the list sorted so reorged and fresh-synced records are identical.
        {
            std::set<COutPoint> setSpentIn;
            for (const CTxIn& in : tx.vin)
                setSpentIn.insert(in.prevout);
            std::vector<COutPoint> vKeep;
            for (const COutPoint& out : house.vOutEscrowChange) {
                if (!setSpentIn.count(out))
                    vKeep.push_back(out);
            }
            if (clm.fEscrowChange)
                vKeep.push_back(COutPoint(tx.GetHash(), 1));
            std::sort(vKeep.begin(), vKeep.end());
            house.vOutEscrowChange = vKeep;
        }
        houseOut = house;
        fHouseChanged = true;
        return true;
    }

    return state.DoS(100, false, REJECT_INVALID, "bad-deposit-op");
}

/** Contextual validation of a pool operation (Phase 3.7 AMM). tx_verify has
 * done the input structure, custody positions and every conservation sum;
 * shape pinned the outputs (escrow pair, payouts, change) to the payload.
 * This does what needs DB state: the payload PRIORS must equal the CPool
 * record byte-exact (which is what makes one-op-per-pool-per-block
 * self-enforcing and the disconnect undo payload-only), the spent custody
 * coins must be THE canonical outpoints the record tracks, the SWAP formula
 * runs with the pool's stored fee, CREATE checks its house (existence,
 * effective-Open, M-of-N charter approval) and pool uniqueness, and every op
 * verifies its payload ECDSA. poolOut always carries the post-op record - the
 * caller stages it under the one-op-per-pool-per-block rule. CREATE is
 * house-status-DEPENDENT but house-state-NEUTRAL (like NOTE_OP_DEMAND): it
 * takes no house slot, but the ATMP cross-op guard must pair it against
 * pending governance ops (the DR-2 template-brick lesson). */
bool CheckPoolOperation(const CTransaction& tx, CValidationState& state, int nHeight,
                        const std::function<bool(uint32_t, CPool&)>& fnGetPool,
                        const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                        CPool& poolOut, CHouse& houseOut, bool& fHouseChanged, bool& fPoolRetired)
{
    fHouseChanged = false;
    fPoolRetired = false;
    const uint256 hashOutputs = BillHashOutputs(tx);
    const uint256 hashPrevouts = PoolHashPrevouts(tx);

    if (tx.nPoolOp == POOL_OP_CREATE) {
        PoolCreate create;
        if (!DecodePoolPayload(tx.vchPoolPayload, create))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-create-payload");

        // One pool per house, forever (nPoolID == nHouseID).
        CPool poolExisting;
        if (fnGetPool(create.nPoolID, poolExisting))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-already-exists");

        CHouse house;
        if (!fnGetHouse(create.nPoolID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-unknown-house");
        // The house charters its own venue - only while effectively Open
        // (operator decision 1). Every LATER pool op is status-UNGATED.
        if (HouseEffectiveStatus(house, nHeight) != HOUSE_STATUS_OPEN)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-create-house-not-open");

        const uint256 sighash = PoolCreateSigHash(create.nPoolID, create.nFeeBps,
                create.nInitNoteUnits, create.amountInitBtx, create.nNoteChangeUnits,
                hashPrevouts, hashOutputs);
        if (!VerifyHouseApprovers(house, create.vApproverIndex, create.vApproverSig,
                sighash, house.nThresholdM, state, "bad-pool-create-approver"))
            return false;
        // The creator (who funds the seed and receives the LP coin) binds the
        // trailer to THIS tx; their note inputs' P2PKH scriptSigs authorize
        // the coins, this sig authorizes the pool semantics.
        if (!CPubKey(create.vchCreatorPubKey).Verify(sighash, create.vchCreatorSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-create-creator-sig");

        uint64_t toCreator = 0, supply0 = 0;
        if (!PoolLpMintInitial(create.nInitNoteUnits, create.amountInitBtx, toCreator, supply0))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-create-seed");

        poolOut.SetNull();
        poolOut.nPoolID = create.nPoolID;
        poolOut.nFeeBps = create.nFeeBps;
        poolOut.nNoteReserve = create.nInitNoteUnits;
        poolOut.amountBtxReserve = create.amountInitBtx;
        poolOut.nLpSupply = supply0;
        poolOut.outNote = COutPoint(tx.GetHash(), 0);
        poolOut.outBtx = COutPoint(tx.GetHash(), 1);
        poolOut.nCreateHeight = nHeight;
        return true;
    }

    if (tx.nPoolOp == POOL_OP_RETIRE) {
        PoolRetire ret;
        if (!DecodePoolPayload(tx.vchPoolPayload, ret))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-payload");

        CPool pool;
        if (!fnGetPool(ret.nPoolID, pool))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-unknown-pool");
        // The payload carries the FULL prior record (incl. nFeeBps + nCreateHeight,
        // which no earlier op needed) so DisconnectBlock rebuilds the deleted
        // record from the payload alone. All five fields must match byte-exact.
        if (pool.nNoteReserve != ret.nPriorNoteReserve ||
                pool.amountBtxReserve != ret.amountPriorBtxReserve ||
                pool.nLpSupply != ret.nPriorLpSupply ||
                pool.nFeeBps != ret.nFeeBps ||
                pool.nCreateHeight != ret.nCreateHeight)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-priors-mismatch");
        // Floor-gated: only the never-issued locked floor may remain (every
        // issued LP share removed). The residual X note-units + Y BTX back NOBODY.
        if (pool.nLpSupply != POOL_MIN_LIQUIDITY)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-not-floor");
        // Spends THE canonical custody pair (tx_verify pinned tags + positions;
        // this pins identity to the record).
        if (tx.vin.size() < 2 || !(tx.vin[0].prevout == pool.outNote) || !(tx.vin[1].prevout == pool.outBtx))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-wrong-escrow-outpoint");

        CHouse house;
        if (!fnGetHouse(ret.nPoolID, house))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-unknown-house");
        // Burning the residual floor note-units is the ONE documented terminal
        // exception to "pool ops never burn units": house.nMintedUnits -= X.
        if (house.nMintedUnits < ret.nPriorNoteReserve)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-underflow");

        // Hybrid auth over the retire sighash. The single-partner path is accepted
        // ONLY at effective Insolvent and mirrors the SETTLE trigger bar exactly
        // (any non-settled partner may trigger) - so insolvency liveness never
        // depends on assembling M-of-N. The M-of-N path is accepted at ANY
        // effective status (operator decision 5).
        const uint256 sighash = PoolRetireSigHash(ret, hashPrevouts, hashOutputs);
        if (!ret.vchTriggerSig.empty()) {
            if (HouseEffectiveStatus(house, nHeight) != HOUSE_STATUS_INSOLVENT)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-trigger-not-insolvent");
            if (ret.nTriggerPartnerIndex >= house.vPartner.size())
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-trigger-partner");
            const HousePartner& partner = house.vPartner[ret.nTriggerPartnerIndex];
            if (partner.status == HOUSE_PARTNER_SETTLED)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-trigger-settled");
            if (!CPubKey(partner.vchPubKey).Verify(sighash, ret.vchTriggerSig))
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-trigger-sig");
        } else {
            if (!VerifyHouseApprovers(house, ret.vApproverIndex, ret.vApproverSig,
                    sighash, house.nThresholdM, state, "bad-pool-retire-approver"))
                return false;
        }

        // Force-pay the floor BTX to P2PKH(vchRedemptionDestPK) at vout[0], value
        // >= Y (the note-side dust + any plain fee inputs cover the rest). The
        // deterministic destination kills the partner-capture race (decision 4);
        // it strands floor-scale value if the redemption key is lost (accepted -
        // liveness is unaffected).
        if (house.vchRedemptionDestPK.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-no-dest");
        const CScript scriptPayout = PoolScriptForPubKey(house.vchRedemptionDestPK);
        if (tx.vout.empty() || tx.vout[0].scriptPubKey != scriptPayout ||
                tx.vout[0].nValue < ret.amountPriorBtxReserve)
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-payout");
        // Terminal: no output may re-create an escrow-shaped coin (it would enter
        // the UTXO set untagged - SETTLE's stray-escrow rule). Shape-checked too;
        // kept here so the contextual path is self-contained.
        for (const CTxOut& out : tx.vout) {
            if (IsPoolEscrowScript(out.scriptPubKey))
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-retire-stray-escrow");
        }

        house.nMintedUnits -= ret.nPriorNoteReserve;
        houseOut = house;
        fHouseChanged = true;
        fPoolRetired = true;
        // poolOut carries only the id: ConnectBlock deletes the record (vPoolRemove)
        // rather than staging an update.
        poolOut.SetNull();
        poolOut.nPoolID = ret.nPoolID;
        return true;
    }

    // ADD_LIQ / REMOVE_LIQ / SWAP share the prior/custody discipline.
    uint32_t nPoolID = 0;
    uint64_t nPriorNote = 0;
    CAmount amountPriorBtx = 0;
    uint64_t nPriorLp = 0;
    PoolAddLiq add;
    PoolRemoveLiq rem;
    PoolSwap swap;
    if (tx.nPoolOp == POOL_OP_ADD_LIQ) {
        if (!DecodePoolPayload(tx.vchPoolPayload, add))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-add-payload");
        nPoolID = add.nPoolID;
        nPriorNote = add.nPriorNoteReserve;
        amountPriorBtx = add.amountPriorBtxReserve;
        nPriorLp = add.nPriorLpSupply;
    } else if (tx.nPoolOp == POOL_OP_REMOVE_LIQ) {
        if (!DecodePoolPayload(tx.vchPoolPayload, rem))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-remove-payload");
        nPoolID = rem.nPoolID;
        nPriorNote = rem.nPriorNoteReserve;
        amountPriorBtx = rem.amountPriorBtxReserve;
        nPriorLp = rem.nPriorLpSupply;
    } else if (tx.nPoolOp == POOL_OP_SWAP) {
        if (!DecodePoolPayload(tx.vchPoolPayload, swap))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-payload");
        nPoolID = swap.nPoolID;
        nPriorNote = swap.nPriorNoteReserve;
        amountPriorBtx = swap.amountPriorBtxReserve;
        nPriorLp = swap.nPriorLpSupply;
    } else {
        return state.DoS(100, false, REJECT_INVALID, "bad-pool-op");
    }

    CPool pool;
    if (!fnGetPool(nPoolID, pool))
        return state.DoS(100, false, REJECT_INVALID, "bad-pool-unknown-pool");

    // The payload's priors must equal the record byte-exact. This is the
    // one-op-per-pool-per-block rule's teeth (a second op binding the same
    // priors cannot connect after the first moved them), the anti-sandwich
    // property, and what lets DisconnectBlock restore from the payload alone.
    if (pool.nNoteReserve != nPriorNote || pool.amountBtxReserve != amountPriorBtx ||
            pool.nLpSupply != nPriorLp)
        return state.DoS(100, false, REJECT_INVALID, "bad-pool-priors-mismatch");

    // The spent custody coins must be THE canonical pair the record tracks
    // (tx_verify checked tags and positions; this pins identity).
    if (tx.vin.size() < 2 || !(tx.vin[0].prevout == pool.outNote) || !(tx.vin[1].prevout == pool.outBtx))
        return state.DoS(100, false, REJECT_INVALID, "bad-pool-wrong-escrow-outpoint");

    if (tx.nPoolOp == POOL_OP_ADD_LIQ) {
        if (!CPubKey(add.vchProviderPubKey).Verify(PoolAddLiqSigHash(add, hashPrevouts, hashOutputs),
                add.vchProviderSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-add-sig");
        // The min-rule formula was verified context-free (payload-pure).
        pool.nNoteReserve += add.nAddNoteUnits;
        pool.amountBtxReserve += add.amountAddBtx;
        pool.nLpSupply += add.nLpMinted;
    }
    else if (tx.nPoolOp == POOL_OP_REMOVE_LIQ) {
        if (!CPubKey(rem.vchProviderPubKey).Verify(PoolRemoveLiqSigHash(rem, hashPrevouts, hashOutputs),
                rem.vchProviderSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-remove-sig");
        // The redeem formula was verified context-free (payload-pure).
        pool.nNoteReserve -= rem.nNoteOut;
        pool.amountBtxReserve -= rem.amountBtxOut;
        pool.nLpSupply -= rem.nBurnLp;
    }
    else { // POOL_OP_SWAP
        if (!CPubKey(swap.vchTraderPubKey).Verify(PoolSwapSigHash(swap, hashPrevouts, hashOutputs),
                swap.vchTraderSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-sig");
        // The x*y=k formula needs the pool's STORED fee - the one check that
        // could not run context-free. minOut <= out was shape-enforced.
        uint64_t out = 0;
        if (swap.nDirection == POOL_SWAP_NOTE_TO_BTX) {
            if (!PoolSwapOut(swap.nAmountIn, pool.nNoteReserve, (uint64_t)pool.amountBtxReserve,
                    pool.nFeeBps, out) || out != swap.nAmountOut)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-formula");
            pool.nNoteReserve += swap.nAmountIn;
            pool.amountBtxReserve -= (CAmount)swap.nAmountOut;
        } else {
            if (!PoolSwapOut(swap.nAmountIn, (uint64_t)pool.amountBtxReserve, pool.nNoteReserve,
                    pool.nFeeBps, out) || out != swap.nAmountOut)
                return state.DoS(100, false, REJECT_INVALID, "bad-pool-swap-formula");
            pool.nNoteReserve -= swap.nAmountOut;
            pool.amountBtxReserve += (CAmount)swap.nAmountIn;
        }
    }

    pool.outNote = COutPoint(tx.GetHash(), 0);
    pool.outBtx = COutPoint(tx.GetHash(), 1);
    poolOut = pool;
    return true;
}

bool CScriptCheck::operator()() {
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    const CScriptWitness *witness = &ptxTo->vin[nIn].scriptWitness;
    return VerifyScript(scriptSig, m_tx_out.scriptPubKey, witness, nFlags, CachingTransactionSignatureChecker(ptxTo, nIn, m_tx_out.nValue, cacheStore, *txdata), &error);
}

int GetSpendHeight(const CCoinsViewCache& inputs)
{
    LOCK(cs_main);
    CBlockIndex* pindexPrev = mapBlockIndex.find(inputs.GetBestBlock())->second;
    return pindexPrev->nHeight + 1;
}


static CuckooCache::cache<uint256, SignatureCacheHasher> scriptExecutionCache;
static uint256 scriptExecutionCacheNonce(GetRandHash());

void InitScriptExecutionCache() {
    // nMaxCacheSize is unsigned. If -maxsigcachesize is set to zero,
    // setup_bytes creates the minimum possible cache (2 elements).
    size_t nMaxCacheSize = std::min(std::max((int64_t)0, gArgs.GetArg("-maxsigcachesize", DEFAULT_MAX_SIG_CACHE_SIZE) / 2), MAX_MAX_SIG_CACHE_SIZE) * ((size_t) 1 << 20);
    size_t nElems = scriptExecutionCache.setup_bytes(nMaxCacheSize);
    LogPrintf("Using %zu MiB out of %zu/2 requested for script execution cache, able to store %zu elements\n",
            (nElems*sizeof(uint256)) >>20, (nMaxCacheSize*2)>>20, nElems);
}

/**
 * Check whether all inputs of this transaction are valid (no double spends, scripts & sigs, amounts)
 * This does not modify the UTXO set.
 *
 * If pvChecks is not nullptr, script checks are pushed onto it instead of being performed inline. Any
 * script checks which are not necessary (eg due to script execution cache hits) are, obviously,
 * not pushed onto pvChecks/run.
 *
 * Setting cacheSigStore/cacheFullScriptStore to false will remove elements from the corresponding cache
 * which are matched. This is useful for checking blocks where we will likely never need the cache
 * entry again.
 *
 * Non-static (and re-declared) in src/test/txvalidationcache_tests.cpp
 */
bool CheckInputs(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks)
{
    if (!tx.IsCoinBase())
    {
        if (pvChecks)
            pvChecks->reserve(tx.vin.size());

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.

        // Skip script verification when connecting blocks under the
        // assumevalid block. Assuming the assumevalid block is valid this
        // is safe because block merkle hashes are still computed and checked,
        // Of course, if an assumed valid block is invalid due to false scriptSigs
        // this optimization would allow an invalid chain to be accepted.
        if (fScriptChecks) {
            // First check if script executions have been cached with the same
            // flags. Note that this assumes that the inputs provided are
            // correct (ie that the transaction hash which is in tx's prevouts
            // properly commits to the scriptPubKey in the inputs view of that
            // transaction).
            uint256 hashCacheEntry;
            // We only use the first 19 bytes of nonce to avoid a second SHA
            // round - giving us 19 + 32 + 4 = 55 bytes (+ 8 + 1 = 64)
            static_assert(55 - sizeof(flags) - 32 >= 128/8, "Want at least 128 bits of nonce for script execution cache");
            CSHA256().Write(scriptExecutionCacheNonce.begin(), 55 - sizeof(flags) - 32).Write(tx.GetWitnessHash().begin(), 32).Write((unsigned char*)&flags, sizeof(flags)).Finalize(hashCacheEntry.begin());
            AssertLockHeld(cs_main); //TODO: Remove this requirement by making CuckooCache not require external locks
            if (scriptExecutionCache.contains(hashCacheEntry, !cacheFullScriptStore)) {
                return true;
            }

            for (unsigned int i = 0; i < tx.vin.size(); i++) {
                const COutPoint &prevout = tx.vin[i].prevout;
                const Coin& coin = inputs.AccessCoin(prevout);
                assert(!coin.IsSpent());

                // We very carefully only pass in things to CScriptCheck which
                // are clearly committed to by tx' witness hash. This provides
                // a sanity check that our caching is not introducing consensus
                // failures through additional data in, eg, the coins being
                // spent being checked as a part of CScriptCheck.

                // Verify signature
                CScriptCheck check(coin.out, tx, i, flags, cacheSigStore, &txdata);
                if (pvChecks) {
                    pvChecks->push_back(CScriptCheck());
                    check.swap(pvChecks->back());
                } else if (!check()) {
                    if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) {
                        // Check whether the failure was caused by a
                        // non-mandatory script verification check, such as
                        // non-standard DER encodings or non-null dummy
                        // arguments; if so, don't trigger DoS protection to
                        // avoid splitting the network between upgraded and
                        // non-upgraded nodes.
                        CScriptCheck check2(coin.out, tx, i,
                                flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, cacheSigStore, &txdata);
                        if (check2())
                            return state.Invalid(false, REJECT_NONSTANDARD, strprintf("non-mandatory-script-verify-flag (%s)", ScriptErrorString(check.GetScriptError())));
                    }
                    // Failures of other flags indicate a transaction that is
                    // invalid in new blocks, e.g. an invalid P2SH. We DoS ban
                    // such nodes as they are not following the protocol. That
                    // said during an upgrade careful thought should be taken
                    // as to the correct behavior - we may want to continue
                    // peering with non-upgraded nodes even after soft-fork
                    // super-majority signaling has occurred.
                    return state.DoS(100,false, REJECT_INVALID, strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(check.GetScriptError())));
                }
            }

            if (cacheFullScriptStore && !pvChecks) {
                // We executed all of the provided scripts, and were told to
                // cache the result. Do so now.
                scriptExecutionCache.insert(hashCacheEntry);
            }
        }
    }

    return true;
}

namespace {

bool UndoWriteToDisk(const CBlockUndo& blockundo, CDiskBlockPos& pos, const uint256& hashBlock, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Write index header
    unsigned int nSize = GetSerializeSize(fileout, blockundo);
    fileout << FLATDATA(messageStart) << nSize;

    // Write undo data
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("%s: ftell failed", __func__);
    pos.nPos = (unsigned int)fileOutPos;
    fileout << blockundo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    fileout << hasher.GetHash();

    return true;
}

static bool UndoReadFromDisk(CBlockUndo& blockundo, const CBlockIndex *pindex)
{
    CDiskBlockPos pos = pindex->GetUndoPos();
    if (pos.IsNull()) {
        return error("%s: no undo data available", __func__);
    }

    // Open history file to read
    CAutoFile filein(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Read block
    uint256 hashChecksum;
    CHashVerifier<CAutoFile> verifier(&filein); // We need a CHashVerifier as reserializing may lose data
    try {
        verifier << pindex->pprev->GetBlockHash();
        verifier >> blockundo;
        filein >> hashChecksum;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    // Verify checksum
    if (hashChecksum != verifier.GetHash())
        return error("%s: Checksum mismatch", __func__);

    return true;
}

/** Abort with a message */
bool AbortNode(const std::string& strMessage, const std::string& userMessage="")
{
    SetMiscWarning(strMessage);
    LogPrintf("*** %s\n", strMessage);
    uiInterface.ThreadSafeMessageBox(
        userMessage.empty() ? _("Error: A fatal internal error occurred, see debug.log for details") : userMessage,
        "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
    return false;
}

bool AbortNode(CValidationState& state, const std::string& strMessage, const std::string& userMessage="")
{
    AbortNode(strMessage, userMessage);
    return state.Error(strMessage);
}

} // namespace

/**
 * Restore the UTXO in a Coin at a given COutPoint
 * @param undo The Coin to be restored.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return A DisconnectResult as an int
 */
int ApplyTxInUndo(Coin&& undo, CCoinsViewCache& view, const COutPoint& out)
{
    bool fClean = true;

    if (view.HaveCoin(out)) fClean = false; // overwriting transaction output

    if (undo.nHeight == 0) {
        // Missing undo metadata (height and coinbase). Older versions included this
        // information only in undo records for the last spend of a transactions'
        // outputs. This implies that it must be present for some other output of the same tx.
        const Coin& alternate = AccessByTxid(view, out.hash);
        if (!alternate.IsSpent()) {
            undo.nHeight = alternate.nHeight;
            undo.fCoinBase = alternate.fCoinBase;
        } else {
            return DISCONNECT_FAILED; // adding output for transaction without known metadata
        }
    }
    // The potential_overwrite parameter to AddCoin is only allowed to be false if we know for
    // sure that the coin did not already exist in the cache. As we have queried for that above
    // using HaveCoin, we don't need to guess. When fClean is false, a coin already existed and
    // it is an overwrite.
    view.AddCoin(out, std::move(undo), !fClean);

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  When FAILED is returned, view is left in an indeterminate state. */
DisconnectResult CChainState::DisconnectBlock(const CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view, bool fSideDB)
{
    bool fClean = true;

    CBlockUndo blockUndo;
    if (!UndoReadFromDisk(blockUndo, pindex)) {
        error("DisconnectBlock(): failure reading undo data");
        return DISCONNECT_FAILED;
    }

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size()) {
        error("DisconnectBlock(): block and undo data inconsistent");
        return DISCONNECT_FAILED;
    }

    // Side-DB lifecycle (3.4 review): the house/bill undo writes go to DISK,
    // so a caller working on a throwaway coins view (VerifyDB's default
    // startup check!) must pass fSideDB=false or every restart would roll
    // the side DBs back without reconnecting them. Additionally each DB is
    // only unwound if its best-block marker shows it actually APPLIED this
    // block (crash-replay exactness); the marker steps back with the undo.
    bool fHouseUndo = false;
    bool fBillUndo = false;
    bool fPoolUndo = false;
    if (fSideDB) {
        uint256 hashHouseBest;
        const bool fHaveHouseMarker = phousetree->GetBestBlock(hashHouseBest) && !hashHouseBest.IsNull();
        fHouseUndo = !fHaveHouseMarker || hashHouseBest == pindex->GetBlockHash();
        uint256 hashBillBest;
        const bool fHaveBillMarker = pbilltree->GetBestBlock(hashBillBest) && !hashBillBest.IsNull();
        fBillUndo = !fHaveBillMarker || hashBillBest == pindex->GetBlockHash();
        uint256 hashPoolBest;
        const bool fHavePoolMarker = ppooltree->GetBestBlock(hashPoolBest) && !hashPoolBest.IsNull();
        fPoolUndo = !fHavePoolMarker || hashPoolBest == pindex->GetBlockHash();
    }

    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = *(block.vtx[i]);
        uint256 hash = tx.GetHash();
        bool is_coinbase = tx.IsCoinBase();

        // Undo BitAssetDB updates
        if (tx.nVersion == TRANSACTION_BITASSET_CREATE_VERSION) {
            // Undo BitAsset creation & revert asset ID #
            uint32_t nIDLast = 0;
            passettree->GetLastAssetID(nIDLast);
            if (!passettree->WriteLastAssetID(nIDLast - 1)) {
                error("DisconnectBlock(): Failed to undo BitAssetDB asset ID #!");
                return DISCONNECT_FAILED;
            }
            if (!passettree->RemoveAsset(nIDLast)) {
                error("DisconnectBlock(): Failed to remove BitAssetDB asset!");
                return DISCONNECT_FAILED;
            }
        }

        // Undo BillDB updates. Every mutation is reconstructible from the tx
        // payload plus current DB state, so no dedicated undo data is needed.
        if (fBillUndo && tx.nVersion == TRANSACTION_BILL_VERSION) {
            if (tx.nBillOp == BILL_OP_ISSUE) {
                uint32_t nIDLast = 0;
                pbilltree->GetLastBillID(nIDLast);

                CBill bill;
                if (!pbilltree->GetBill(nIDLast, bill) || bill.txidIssue != hash) {
                    error("DisconnectBlock(): Bill issue undo mismatch!");
                    return DISCONNECT_FAILED;
                }
                if (!pbilltree->RemoveBill(nIDLast)) {
                    error("DisconnectBlock(): Failed to remove bill!");
                    return DISCONNECT_FAILED;
                }
                if (!pbilltree->WriteLastBillID(nIDLast - 1)) {
                    error("DisconnectBlock(): Failed to undo bill ID #!");
                    return DISCONNECT_FAILED;
                }
            }
            else if (tx.nBillOp == BILL_OP_ENDORSE) {
                BillEndorse endorse;
                CBill bill;
                if (!DecodeBillPayload(tx.vchBillPayload, endorse) ||
                        !pbilltree->GetBill(endorse.nBillID, bill) ||
                        bill.vEndorsement.empty()) {
                    error("DisconnectBlock(): Failed to undo bill endorsement!");
                    return DISCONNECT_FAILED;
                }
                bill.vchHolderPubKey = bill.vEndorsement.back().vchFrom;
                bill.vEndorsement.pop_back();

                // Restore the prior title outpoint from this tx's spent
                // title input (its undo Coin carries the fBill tag)
                bill.outTitle.SetNull();
                if (i > 0) {
                    const CTxUndo& txundoBill = blockUndo.vtxundo[i - 1];
                    for (size_t j = 0; j < tx.vin.size() && j < txundoBill.vprevout.size(); j++) {
                        if (txundoBill.vprevout[j].fBill) {
                            bill.outTitle = tx.vin[j].prevout;
                            break;
                        }
                    }
                }
                if (bill.outTitle.IsNull()) {
                    error("DisconnectBlock(): Failed to restore bill title outpoint!");
                    return DISCONNECT_FAILED;
                }
                if (!pbilltree->WriteBill(bill)) {
                    error("DisconnectBlock(): Failed to write bill endorsement undo!");
                    return DISCONNECT_FAILED;
                }
            }
            else if (tx.nBillOp == BILL_OP_RETIRE || tx.nBillOp == BILL_OP_CLAIM) {
                uint32_t nBillID = 0;
                if (tx.nBillOp == BILL_OP_RETIRE) {
                    BillRetire retire;
                    if (!DecodeBillPayload(tx.vchBillPayload, retire)) {
                        error("DisconnectBlock(): Failed to decode bill retire undo!");
                        return DISCONNECT_FAILED;
                    }
                    nBillID = retire.nBillID;
                } else {
                    BillClaim claim;
                    if (!DecodeBillPayload(tx.vchBillPayload, claim)) {
                        error("DisconnectBlock(): Failed to decode bill claim undo!");
                        return DISCONNECT_FAILED;
                    }
                    nBillID = claim.nBillID;
                }

                CBill bill;
                if (!pbilltree->GetBill(nBillID, bill)) {
                    error("DisconnectBlock(): Failed to load bill for status undo!");
                    return DISCONNECT_FAILED;
                }
                bill.status = BILL_STATUS_ACTIVE;
                if (!pbilltree->WriteBill(bill)) {
                    error("DisconnectBlock(): Failed to write bill status undo!");
                    return DISCONNECT_FAILED;
                }
            }
        }

        // Undo HouseDB updates. One house op per house per block (consensus)
        // keeps every inverse deterministic from the payload + current state.
        if (fHouseUndo && tx.nVersion == TRANSACTION_HOUSE_VERSION) {
            if (tx.nHouseOp == HOUSE_OP_REGISTER) {
                uint32_t nIDLast = 0;
                phousetree->GetLastHouseID(nIDLast);

                CHouse house;
                if (!phousetree->GetHouse(nIDLast, house) || house.txidRegister != hash) {
                    error("DisconnectBlock(): House register undo mismatch!");
                    return DISCONNECT_FAILED;
                }
                if (!phousetree->RemoveHouse(nIDLast)) {
                    error("DisconnectBlock(): Failed to remove house!");
                    return DISCONNECT_FAILED;
                }
                if (!phousetree->WriteLastHouseID(nIDLast - 1)) {
                    error("DisconnectBlock(): Failed to undo house ID #!");
                    return DISCONNECT_FAILED;
                }
            }
            else if (tx.nHouseOp == HOUSE_OP_TOPUP) {
                HouseTopup topup;
                CHouse house;
                if (!DecodeHousePayload(tx.vchHousePayload, topup) ||
                        !phousetree->GetHouse(topup.nHouseID, house) ||
                        topup.nPartnerIndex >= house.vPartner.size()) {
                    error("DisconnectBlock(): Failed to undo house topup!");
                    return DISCONNECT_FAILED;
                }
                HousePartner& partner = house.vPartner[topup.nPartnerIndex];
                partner.amountPledge -= tx.vout[0].nValue;
                const COutPoint added(hash, 0);
                for (size_t j2 = 0; j2 < partner.vOutPledge.size(); j2++) {
                    if (partner.vOutPledge[j2] == added) {
                        partner.vOutPledge.erase(partner.vOutPledge.begin() + j2);
                        break;
                    }
                }
                if (!phousetree->WriteHouse(house)) {
                    error("DisconnectBlock(): Failed to write house topup undo!");
                    return DISCONNECT_FAILED;
                }
            }
            else if (tx.nHouseOp == HOUSE_OP_ADMIT) {
                HouseAdmit admit;
                CHouse house;
                if (!DecodeHousePayload(tx.vchHousePayload, admit) ||
                        !phousetree->GetHouse(admit.nHouseID, house) ||
                        house.vPartner.empty() ||
                        house.vPartner.back().vchPubKey != admit.vchNewPubKey) {
                    error("DisconnectBlock(): Failed to undo house admit!");
                    return DISCONNECT_FAILED;
                }
                house.vPartner.pop_back();
                if (!phousetree->WriteHouse(house)) {
                    error("DisconnectBlock(): Failed to write house admit undo!");
                    return DISCONNECT_FAILED;
                }
            }
            else if (tx.nHouseOp == HOUSE_OP_EXIT) {
                HouseExit ex;
                CHouse house;
                if (!DecodeHousePayload(tx.vchHousePayload, ex) ||
                        !phousetree->GetHouse(ex.nHouseID, house) ||
                        ex.nPartnerIndex >= house.vPartner.size() ||
                        house.vPartner[ex.nPartnerIndex].status != HOUSE_PARTNER_TAIL) {
                    error("DisconnectBlock(): Failed to undo house exit!");
                    return DISCONNECT_FAILED;
                }
                house.vPartner[ex.nPartnerIndex].status = HOUSE_PARTNER_ACTIVE;
                house.vPartner[ex.nPartnerIndex].nTailUnlockHeight = 0;
                if (!phousetree->WriteHouse(house)) {
                    error("DisconnectBlock(): Failed to write house exit undo!");
                    return DISCONNECT_FAILED;
                }
            }
            else if (tx.nHouseOp == HOUSE_OP_WINDDOWN) {
                HouseWinddown wd;
                CHouse house;
                if (!DecodeHousePayload(tx.vchHousePayload, wd) ||
                        !phousetree->GetHouse(wd.nHouseID, house) ||
                        house.status != HOUSE_STATUS_WOUNDDOWN) {
                    error("DisconnectBlock(): Failed to undo house winddown!");
                    return DISCONNECT_FAILED;
                }
                // Reactivate exactly the partners this winddown tailed: their
                // unlock height carries this block's stamp (solo: height;
                // multi: height + tail). Earlier tails have strictly lower
                // stamps - the one-op-per-house-per-block rule guarantees no
                // same-height ambiguity.
                const bool fSolo = (house.nTier == HOUSE_TIER_BONDED_SOLO ||
                                    house.nTier == HOUSE_TIER_ENCUMBERED_SOLO);
                const uint32_t nStamp = fSolo ? (uint32_t)pindex->nHeight
                                              : (uint32_t)pindex->nHeight + HOUSE_TAIL_BLOCKS;
                house.status = HOUSE_STATUS_OPEN;
                for (HousePartner& partner : house.vPartner) {
                    if (partner.status == HOUSE_PARTNER_TAIL && partner.nTailUnlockHeight == nStamp) {
                        partner.status = HOUSE_PARTNER_ACTIVE;
                        partner.nTailUnlockHeight = 0;
                    }
                }
                if (!phousetree->WriteHouse(house)) {
                    error("DisconnectBlock(): Failed to write house winddown undo!");
                    return DISCONNECT_FAILED;
                }
            }
            else if (tx.nHouseOp == HOUSE_OP_RECLAIM) {
                HouseReclaim rec;
                CHouse house;
                if (!DecodeHousePayload(tx.vchHousePayload, rec) ||
                        !phousetree->GetHouse(rec.nHouseID, house) ||
                        rec.nPartnerIndex >= house.vPartner.size()) {
                    error("DisconnectBlock(): Failed to undo house reclaim!");
                    return DISCONNECT_FAILED;
                }
                // A reclaim at stored-Insolvent was the whole-house residual
                // SETTLE: connect only flipped partner statuses to 'x' (the
                // pledge lists stayed intact; the coins return via the generic
                // undo), so the inverse is statuses back - 'x' partners revert
                // to tail/active, derived from nTailUnlockHeight (only EXIT /
                // WINDDOWN ever set it non-zero). If the settle itself
                // materialized insolvency (zero-liability lazy path), the
                // height stamp matches this block: revert the snapshot too.
                if (house.status == HOUSE_STATUS_INSOLVENT) {
                    for (HousePartner& partner : house.vPartner) {
                        if (partner.status == HOUSE_PARTNER_SETTLED)
                            partner.status = partner.nTailUnlockHeight != 0 ? HOUSE_PARTNER_TAIL
                                                                            : HOUSE_PARTNER_ACTIVE;
                    }
                    if (house.nInsolventHeight == (uint32_t)pindex->nHeight) {
                        house.status = HOUSE_STATUS_OPEN;
                        house.nInsolventHeight = 0;
                        house.nInsolventUnits = 0;
                        house.amountInsolventPot = 0;
                        house.nInsolventDepositPrincipal = 0;   // 3.8: the deposit snapshot too
                        for (HousePartner& p : house.vPartner)
                            p.amountInsolventPledge = 0;
                    }
                    if (!phousetree->WriteHouse(house)) {
                        error("DisconnectBlock(): Failed to write house settle undo!");
                        return DISCONNECT_FAILED;
                    }
                } else {
                    // Restore the reclaimed pledge outpoints from this tx's spent
                    // inputs (their undo Coins carry the fHouseEscrow tag), then
                    // canonicalize order so the restored record is byte-identical to
                    // the never-reorged one (the connect prune also sorts).
                    HousePartner& partner = house.vPartner[rec.nPartnerIndex];
                    size_t nRestored = 0;
                    if (i > 0) {
                        const CTxUndo& txundoHouse = blockUndo.vtxundo[i - 1];
                        for (size_t j2 = 0; j2 < tx.vin.size() && j2 < txundoHouse.vprevout.size(); j2++) {
                            if (txundoHouse.vprevout[j2].fHouseEscrow) {
                                partner.vOutPledge.push_back(tx.vin[j2].prevout);
                                nRestored++;
                            }
                        }
                    }
                    // A RECLAIM always spends >= 1 escrow input (tx_verify guard), so
                    // the undo must restore >= 1 - else the record is silently
                    // corrupted (mirrors the bill-endorse undo's restore guard).
                    if (nRestored == 0) {
                        error("DisconnectBlock(): House reclaim undo restored no pledge outpoints!");
                        return DISCONNECT_FAILED;
                    }
                    std::sort(partner.vOutPledge.begin(), partner.vOutPledge.end());
                    if (!phousetree->WriteHouse(house)) {
                        error("DisconnectBlock(): Failed to write house reclaim undo!");
                        return DISCONNECT_FAILED;
                    }
                }
            }
            else if (tx.nHouseOp == HOUSE_OP_ATTEST) {
                // Connect required the payload priors to equal the DB values,
                // so restoring from the payload alone is byte-exact.
                HouseAttest att;
                CHouse house;
                if (!DecodeHousePayload(tx.vchHousePayload, att) ||
                        !phousetree->GetHouse(att.nHouseID, house)) {
                    error("DisconnectBlock(): Failed to undo house attest!");
                    return DISCONNECT_FAILED;
                }
                house.nLastAttestHeight = att.nPrevLastAttestHeight;
                house.nStressSinceHeight = att.nPrevStressSince;
                house.amountLastAttestReserves = att.amountPrevReserves;
                // A recovery attestation may have LIFTED a deferral (3.5) -
                // the priors restore that too, byte-exact (incl. the DR-2
                // episode-end stamp).
                house.nDeferInvokedHeight = att.nPrevDeferInvokedHeight;
                house.nDeferRenewals = att.nPrevDeferRenewals;
                house.nDeferCumBlocks = att.nPrevDeferCumBlocks;
                house.nDeferEndedHeight = att.nPrevDeferEndedHeight;
                if (!phousetree->WriteHouse(house)) {
                    error("DisconnectBlock(): Failed to write house attest undo!");
                    return DISCONNECT_FAILED;
                }
            }
            else if (tx.nHouseOp == HOUSE_OP_DEFER) {
                // Connect set invoked=height, renewals=0, activations++,
                // lastActivation=height, with the prior lastActivation carried
                // in the payload - so the inverse is exact.
                HouseDefer def;
                CHouse house;
                if (!DecodeHousePayload(tx.vchHousePayload, def) ||
                        !phousetree->GetHouse(def.nHouseID, house) ||
                        house.nDeferActivations == 0) {
                    error("DisconnectBlock(): Failed to undo house defer!");
                    return DISCONNECT_FAILED;
                }
                house.nDeferInvokedHeight = 0;
                house.nDeferRenewals = 0;
                house.nDeferActivations--;
                house.nDeferLastActivation = def.nPrevLastActivation;
                // Drop the till lock this DEFER created (3.5 D11)
                {
                    const COutPoint outLock(hash, 0);
                    std::vector<COutPoint> vKeep;
                    for (const COutPoint& out : house.vOutReserveLock) {
                        if (!(out == outLock))
                            vKeep.push_back(out);
                    }
                    house.vOutReserveLock = vKeep;
                }
                if (!phousetree->WriteHouse(house)) {
                    error("DisconnectBlock(): Failed to write house defer undo!");
                    return DISCONNECT_FAILED;
                }
            }
            else if (tx.nHouseOp == HOUSE_OP_RENEW) {
                HouseRenew ren;
                CHouse house;
                if (!DecodeHousePayload(tx.vchHousePayload, ren) ||
                        !phousetree->GetHouse(ren.nHouseID, house) ||
                        house.nDeferRenewals == 0) {
                    error("DisconnectBlock(): Failed to undo house renew!");
                    return DISCONNECT_FAILED;
                }
                house.nDeferRenewals--;
                if (!phousetree->WriteHouse(house)) {
                    error("DisconnectBlock(): Failed to write house renew undo!");
                    return DISCONNECT_FAILED;
                }
            }
            else if (tx.nHouseOp == HOUSE_OP_RELEASE) {
                // Restore the reserve-lock outpoints this release spent (their
                // undo Coins carry fHouseEscrow), canonically sorted.
                HouseRelease rel;
                CHouse house;
                if (!DecodeHousePayload(tx.vchHousePayload, rel) ||
                        !phousetree->GetHouse(rel.nHouseID, house)) {
                    error("DisconnectBlock(): Failed to undo house release!");
                    return DISCONNECT_FAILED;
                }
                size_t nRestored = 0;
                if (i > 0) {
                    const CTxUndo& txundoRel = blockUndo.vtxundo[i - 1];
                    for (size_t j2 = 0; j2 < tx.vin.size() && j2 < txundoRel.vprevout.size(); j2++) {
                        if (txundoRel.vprevout[j2].fHouseEscrow) {
                            house.vOutReserveLock.push_back(tx.vin[j2].prevout);
                            nRestored++;
                        }
                    }
                }
                if (nRestored == 0) {
                    error("DisconnectBlock(): House release undo restored no reserve locks!");
                    return DISCONNECT_FAILED;
                }
                std::sort(house.vOutReserveLock.begin(), house.vOutReserveLock.end());
                if (!phousetree->WriteHouse(house)) {
                    error("DisconnectBlock(): Failed to write house release undo!");
                    return DISCONNECT_FAILED;
                }
            }
        }

        // Undo note MINT / REDEEM effect on the house counter. TRANSFER changes
        // no house state (its coins are handled by the generic output/undo
        // loops below). One house-state-changing op per house per block makes
        // this a per-op inverse (no net-delta).
        if (fHouseUndo && tx.nVersion == TRANSACTION_DEPOSIT_VERSION) {
            // ORIGINATE grew the D accounting; the inverse re-reads the DB house
            // and subtracts the batch's principal AND the 128-bit weighted-maturity
            // delta (recomputed from the payload's absolute maturities). One
            // house-state change per block makes this a clean per-op inverse.
            if (tx.nDepositOp == DEPOSIT_OP_ORIGINATE) {
                DepositOriginate org;
                uint64_t total = 0;
                CHouse house;
                if (!DecodeDepositPayload(tx.vchDepositPayload, org) ||
                        !SumDepositPrincipal(org.vPrincipal, total) ||
                        !phousetree->GetHouse(org.nHouseID, house) ||
                        house.nDepositUnits < total) {
                    error("DisconnectBlock(): Failed to undo deposit originate!");
                    return DISCONNECT_FAILED;
                }
                unsigned __int128 wtDelta = 0;
                for (size_t j = 0; j < org.vMaturityHeight.size() && j < org.vPrincipal.size(); j++)
                    wtDelta += (unsigned __int128)org.vPrincipal[j] * (unsigned __int128)org.vMaturityHeight[j];
                house.nDepositUnits -= total;
                house.SetDepositWtMaturity(house.DepositWtMaturity() - wtDelta);
                if (!phousetree->WriteHouse(house)) {
                    error("DisconnectBlock(): Failed to write deposit originate undo!");
                    return DISCONNECT_FAILED;
                }
            }
            // WITHDRAW burned a receipt and shrank D; the inverse restores it. The
            // principal + maturity come from the burned receipt's undo Coin (it
            // carries fDeposit + terms).
            else if (tx.nDepositOp == DEPOSIT_OP_WITHDRAW) {
                DepositWithdraw wd;
                CHouse house;
                if (!DecodeDepositPayload(tx.vchDepositPayload, wd) ||
                        !phousetree->GetHouse(wd.nHouseID, house)) {
                    error("DisconnectBlock(): Failed to undo deposit withdraw!");
                    return DISCONNECT_FAILED;
                }
                uint64_t p = 0; uint32_t m = 0; bool fFound = false;
                if (i > 0) {
                    const CTxUndo& txundoDep = blockUndo.vtxundo[i - 1];
                    for (const Coin& c : txundoDep.vprevout) {
                        if (c.fDeposit) { p = c.nDepositPrincipal; m = c.nDepositMaturityHeight; fFound = true; break; }
                    }
                }
                if (!fFound || p == 0 || house.nDepositUnits > (uint64_t)MAX_MONEY - p) {
                    error("DisconnectBlock(): deposit withdraw undo receipt missing!");
                    return DISCONNECT_FAILED;
                }
                house.nDepositUnits += p;
                house.SetDepositWtMaturity(house.DepositWtMaturity() + (unsigned __int128)p * (unsigned __int128)m);
                if (!phousetree->WriteHouse(house)) {
                    error("DisconnectBlock(): Failed to write deposit withdraw undo!");
                    return DISCONNECT_FAILED;
                }
            }
            // CLAIM burned a receipt for its subordinated share; the inverse
            // restores D (like WITHDRAW), restores the escrow change bookkeeping
            // (like the note CLAIM), and reverts the insolvency snapshot if THIS
            // claim materialized it (stamp-match).
            else if (tx.nDepositOp == DEPOSIT_OP_CLAIM) {
                DepositClaim clm;
                CHouse house;
                if (!DecodeDepositPayload(tx.vchDepositPayload, clm) ||
                        !phousetree->GetHouse(clm.nHouseID, house)) {
                    error("DisconnectBlock(): Failed to undo deposit claim!");
                    return DISCONNECT_FAILED;
                }
                uint64_t p = 0; uint32_t m = 0; bool fFound = false;
                if (i > 0) {
                    const CTxUndo& txundoDep = blockUndo.vtxundo[i - 1];
                    for (const Coin& c : txundoDep.vprevout) {
                        if (c.fDeposit) { p = c.nDepositPrincipal; m = c.nDepositMaturityHeight; fFound = true; break; }
                    }
                }
                if (!fFound || p == 0 || house.nDepositUnits > (uint64_t)MAX_MONEY - p) {
                    error("DisconnectBlock(): deposit claim undo receipt missing!");
                    return DISCONNECT_FAILED;
                }
                house.nDepositUnits += p;
                house.SetDepositWtMaturity(house.DepositWtMaturity() + (unsigned __int128)p * (unsigned __int128)m);
                // Restore the escrow-change bookkeeping (identical to note CLAIM).
                {
                    const COutPoint outChange(hash, 1);
                    std::vector<COutPoint> vRestore;
                    for (const COutPoint& out : house.vOutEscrowChange) {
                        if (!(out == outChange))
                            vRestore.push_back(out);
                    }
                    std::set<COutPoint> setPledge;
                    for (const HousePartner& pr : house.vPartner)
                        setPledge.insert(pr.vOutPledge.begin(), pr.vOutPledge.end());
                    if (i > 0) {
                        const CTxUndo& txundoClaim = blockUndo.vtxundo[i - 1];
                        for (size_t j2 = 0; j2 < tx.vin.size() && j2 < txundoClaim.vprevout.size(); j2++) {
                            if (txundoClaim.vprevout[j2].fHouseEscrow &&
                                    !setPledge.count(tx.vin[j2].prevout))
                                vRestore.push_back(tx.vin[j2].prevout);
                        }
                    }
                    std::sort(vRestore.begin(), vRestore.end());
                    house.vOutEscrowChange = vRestore;
                }
                if (house.nInsolventHeight == (uint32_t)pindex->nHeight) {
                    house.status = HOUSE_STATUS_OPEN;
                    house.nInsolventHeight = 0;
                    house.nInsolventUnits = 0;
                    house.amountInsolventPot = 0;
                    house.nInsolventDepositPrincipal = 0;
                    for (HousePartner& pr : house.vPartner)
                        pr.amountInsolventPledge = 0;
                }
                if (!phousetree->WriteHouse(house)) {
                    error("DisconnectBlock(): Failed to write deposit claim undo!");
                    return DISCONNECT_FAILED;
                }
            }
            // TRANSFER changes no house state.
        }

        // Undo PoolDB updates (Phase 3.7). Every op bound the pool's PRIOR
        // (X, Y, S) byte-exact in its payload, so the record restores from
        // the payload alone; the prior custody outpoints are the op's own
        // fixed-position vin. CREATE undo deletes the record. One op per
        // pool per block makes each a clean per-op inverse.
        if (fPoolUndo && tx.nVersion == TRANSACTION_POOL_VERSION) {
            if (tx.nPoolOp == POOL_OP_CREATE) {
                PoolCreate create;
                CPool pool;
                if (!DecodePoolPayload(tx.vchPoolPayload, create) ||
                        !ppooltree->GetPool(create.nPoolID, pool) ||
                        pool.nCreateHeight != pindex->nHeight) {
                    error("DisconnectBlock(): Failed to undo pool create!");
                    return DISCONNECT_FAILED;
                }
                if (!ppooltree->RemovePool(create.nPoolID)) {
                    error("DisconnectBlock(): Failed to remove pool!");
                    return DISCONNECT_FAILED;
                }
            }
            else if (tx.nPoolOp == POOL_OP_ADD_LIQ || tx.nPoolOp == POOL_OP_REMOVE_LIQ ||
                     tx.nPoolOp == POOL_OP_SWAP) {
                uint32_t nPoolID = 0;
                uint64_t nPriorNote = 0;
                CAmount amountPriorBtx = 0;
                uint64_t nPriorLp = 0;
                bool fDecoded = false;
                if (tx.nPoolOp == POOL_OP_ADD_LIQ) {
                    PoolAddLiq add;
                    if (DecodePoolPayload(tx.vchPoolPayload, add)) {
                        nPoolID = add.nPoolID; nPriorNote = add.nPriorNoteReserve;
                        amountPriorBtx = add.amountPriorBtxReserve; nPriorLp = add.nPriorLpSupply;
                        fDecoded = true;
                    }
                } else if (tx.nPoolOp == POOL_OP_REMOVE_LIQ) {
                    PoolRemoveLiq rem;
                    if (DecodePoolPayload(tx.vchPoolPayload, rem)) {
                        nPoolID = rem.nPoolID; nPriorNote = rem.nPriorNoteReserve;
                        amountPriorBtx = rem.amountPriorBtxReserve; nPriorLp = rem.nPriorLpSupply;
                        fDecoded = true;
                    }
                } else {
                    PoolSwap swp;
                    if (DecodePoolPayload(tx.vchPoolPayload, swp)) {
                        nPoolID = swp.nPoolID; nPriorNote = swp.nPriorNoteReserve;
                        amountPriorBtx = swp.amountPriorBtxReserve; nPriorLp = swp.nPriorLpSupply;
                        fDecoded = true;
                    }
                }
                CPool pool;
                if (!fDecoded || !ppooltree->GetPool(nPoolID, pool) ||
                        !(pool.outNote == COutPoint(hash, 0)) || !(pool.outBtx == COutPoint(hash, 1)) ||
                        tx.vin.size() < 2) {
                    error("DisconnectBlock(): Failed to undo pool op!");
                    return DISCONNECT_FAILED;
                }
                pool.nNoteReserve = nPriorNote;
                pool.amountBtxReserve = amountPriorBtx;
                pool.nLpSupply = nPriorLp;
                pool.outNote = tx.vin[0].prevout;
                pool.outBtx = tx.vin[1].prevout;
                if (!ppooltree->WritePool(pool)) {
                    error("DisconnectBlock(): Failed to write pool op undo!");
                    return DISCONNECT_FAILED;
                }
            }
            else if (tx.nPoolOp == POOL_OP_RETIRE) {
                // The record was DELETED at connect; rebuild it in full from the
                // payload (which carried X, Y, S, feeBps AND createHeight - no
                // earlier op needed the last two). The custody pair is the RETIRE's
                // own fixed-position vin; the coins are restored by the generic
                // CTxUndo. It must currently be absent.
                PoolRetire ret;
                if (!DecodePoolPayload(tx.vchPoolPayload, ret) || tx.vin.size() < 2 ||
                        ppooltree->HavePool(ret.nPoolID)) {
                    error("DisconnectBlock(): Failed to undo pool retire (record present)!");
                    return DISCONNECT_FAILED;
                }
                CPool pool;
                pool.SetNull();
                pool.nPoolID = ret.nPoolID;
                pool.nFeeBps = ret.nFeeBps;
                pool.nNoteReserve = ret.nPriorNoteReserve;
                pool.amountBtxReserve = ret.amountPriorBtxReserve;
                pool.nLpSupply = ret.nPriorLpSupply;
                pool.outNote = tx.vin[0].prevout;
                pool.outBtx = tx.vin[1].prevout;
                pool.nCreateHeight = ret.nCreateHeight;
                if (!ppooltree->WritePool(pool)) {
                    error("DisconnectBlock(): Failed to rebuild retired pool!");
                    return DISCONNECT_FAILED;
                }
            }
        }

        // RETIRE also burned X note-units from the house (terminal exception);
        // restore them. Gated on the HouseDB marker INDEPENDENTLY of the pool
        // rebuild above - the two side DBs disconnect on their own markers.
        if (fHouseUndo && tx.nVersion == TRANSACTION_POOL_VERSION && tx.nPoolOp == POOL_OP_RETIRE) {
            PoolRetire ret;
            CHouse house;
            if (!DecodePoolPayload(tx.vchPoolPayload, ret) ||
                    !phousetree->GetHouse(ret.nPoolID, house) ||
                    house.nMintedUnits + ret.nPriorNoteReserve < house.nMintedUnits) {
                error("DisconnectBlock(): Failed to undo pool retire (house)!");
                return DISCONNECT_FAILED;
            }
            house.nMintedUnits += ret.nPriorNoteReserve;
            if (!phousetree->WriteHouse(house)) {
                error("DisconnectBlock(): Failed to write pool retire house undo!");
                return DISCONNECT_FAILED;
            }
        }

        if (fHouseUndo && tx.nVersion == TRANSACTION_NOTE_VERSION) {
            if (tx.nNoteOp == NOTE_OP_MINT) {
                NoteMint mint;
                uint64_t total = 0;
                CHouse house;
                if (!DecodeNotePayload(tx.vchNotePayload, mint) ||
                        !SumNoteUnits(mint.vUnits, total) ||
                        !phousetree->GetHouse(mint.nHouseID, house) ||
                        house.nMintedUnits < total) {
                    error("DisconnectBlock(): Failed to undo note mint!");
                    return DISCONNECT_FAILED;
                }
                house.nMintedUnits -= total;
                if (!phousetree->WriteHouse(house)) {
                    error("DisconnectBlock(): Failed to write note mint undo!");
                    return DISCONNECT_FAILED;
                }
            }
            else if (tx.nNoteOp == NOTE_OP_REDEEM) {
                // U = the units burned = the spent note inputs' units, recovered
                // from this tx's undo Coins (they carry fNote + nNoteUnits).
                NoteRedeem redeem;
                CHouse house;
                if (!DecodeNotePayload(tx.vchNotePayload, redeem) ||
                        !phousetree->GetHouse(redeem.nHouseID, house)) {
                    error("DisconnectBlock(): Failed to undo note redeem!");
                    return DISCONNECT_FAILED;
                }
                uint64_t U = 0;
                if (i > 0) {
                    const CTxUndo& txundoNote = blockUndo.vtxundo[i - 1];
                    for (size_t j2 = 0; j2 < txundoNote.vprevout.size(); j2++) {
                        if (txundoNote.vprevout[j2].fNote)
                            U += txundoNote.vprevout[j2].nNoteUnits;
                    }
                }
                if (U == 0 || house.nMintedUnits > (uint64_t)MAX_MONEY - U) {
                    error("DisconnectBlock(): Note redeem undo unit mismatch!");
                    return DISCONNECT_FAILED;
                }
                house.nMintedUnits += U;
                // Drop the brassage outpoint this redeem added to the pot (3.5).
                if (redeem.fBrassage) {
                    const COutPoint outBrassage(hash, 1);
                    for (size_t j2 = 0; j2 < house.vOutEscrowChange.size(); j2++) {
                        if (house.vOutEscrowChange[j2] == outBrassage) {
                            house.vOutEscrowChange.erase(house.vOutEscrowChange.begin() + j2);
                            break;
                        }
                    }
                }
                if (!phousetree->WriteHouse(house)) {
                    error("DisconnectBlock(): Failed to write note redeem undo!");
                    return DISCONNECT_FAILED;
                }
            }
            else if (tx.nNoteOp == NOTE_OP_CLAIM) {
                // Same U recovery as REDEEM; additionally, if THIS claim was
                // the one that materialized insolvency (its height stamp is on
                // the record - one house-state op per house per block makes
                // the match unambiguous), revert the snapshot: stored status
                // can only have been 'o' before materialization. The escrow
                // coins spent / re-tagged move via the generic undo loops.
                NoteClaim claim;
                CHouse house;
                if (!DecodeNotePayload(tx.vchNotePayload, claim) ||
                        !phousetree->GetHouse(claim.nHouseID, house)) {
                    error("DisconnectBlock(): Failed to undo note claim!");
                    return DISCONNECT_FAILED;
                }
                uint64_t U = 0;
                if (i > 0) {
                    const CTxUndo& txundoNote = blockUndo.vtxundo[i - 1];
                    for (size_t j2 = 0; j2 < txundoNote.vprevout.size(); j2++) {
                        if (txundoNote.vprevout[j2].fNote)
                            U += txundoNote.vprevout[j2].nNoteUnits;
                    }
                }
                if (U == 0 || house.nMintedUnits > (uint64_t)MAX_MONEY - U) {
                    error("DisconnectBlock(): Note claim undo unit mismatch!");
                    return DISCONNECT_FAILED;
                }
                house.nMintedUnits += U;
                // Exact inverse of the connect-side change bookkeeping: drop
                // the change outpoint this claim created, and restore the
                // change coins it CONSUMED. A spent escrow input is a change
                // coin exactly when it is not in any partner's pledge list
                // (claims never prune those; only RECLAIM does).
                {
                    const COutPoint outChange(hash, 1);
                    std::vector<COutPoint> vRestore;
                    for (const COutPoint& out : house.vOutEscrowChange) {
                        if (!(out == outChange))
                            vRestore.push_back(out);
                    }
                    std::set<COutPoint> setPledge;
                    for (const HousePartner& p : house.vPartner)
                        setPledge.insert(p.vOutPledge.begin(), p.vOutPledge.end());
                    if (i > 0) {
                        const CTxUndo& txundoClaim = blockUndo.vtxundo[i - 1];
                        for (size_t j2 = 0; j2 < tx.vin.size() && j2 < txundoClaim.vprevout.size(); j2++) {
                            if (txundoClaim.vprevout[j2].fHouseEscrow &&
                                    !setPledge.count(tx.vin[j2].prevout))
                                vRestore.push_back(tx.vin[j2].prevout);
                        }
                    }
                    std::sort(vRestore.begin(), vRestore.end());
                    house.vOutEscrowChange = vRestore;
                }
                if (house.nInsolventHeight == (uint32_t)pindex->nHeight) {
                    house.status = HOUSE_STATUS_OPEN;
                    house.nInsolventHeight = 0;
                    house.nInsolventUnits = 0;
                    house.amountInsolventPot = 0;
                    house.nInsolventDepositPrincipal = 0;   // 3.8: the deposit snapshot too
                    for (HousePartner& p : house.vPartner)
                        p.amountInsolventPledge = 0;
                }
                if (!phousetree->WriteHouse(house)) {
                    error("DisconnectBlock(): Failed to write note claim undo!");
                    return DISCONNECT_FAILED;
                }
            }
        }

        // Check that all outputs are available and match the outputs in the block itself
        // exactly.
        //
        // Also check for withdrawal bundles and restore the status of withdrawals
        for (size_t o = 0; o < tx.vout.size(); o++) {
            const CScript& scriptPubKey = tx.vout[o].scriptPubKey;
            if (!scriptPubKey.IsUnspendable()) {
                COutPoint out(hash, o);
                Coin coin;
                bool fBitAsset = false;
                bool fBitAssetControl = false;
                uint32_t nAssetID = 0;
                bool is_spent = view.SpendCoin(out, fBitAsset, fBitAssetControl, nAssetID, &coin);
                if (!is_spent || tx.vout[o] != coin.out || pindex->nHeight != coin.nHeight || is_coinbase != coin.fCoinBase) {
                    fClean = false; // transaction output mismatch
                }
            }

            // If this output is a withdrawal bundle database entry, reset the
            // status of withdrawals
            std::vector<unsigned char> vch;
            if (scriptPubKey.IsSidechainObj(vch)) {
                SidechainObj *obj = ParseSidechainObj(vch);
                if (!obj) {
                    error("DisconnectBlock(): failure reading sidechain obj");
                    return DISCONNECT_FAILED;
                }

                if (obj->sidechainop == DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP) {
                    const SidechainWithdrawalBundle *withdrawalBundle = (const SidechainWithdrawalBundle *) obj;

                    std::vector<SidechainWithdrawal> vWithdrawal;
                    for (const uint256& id : withdrawalBundle->vWithdrawalID) {
                        SidechainWithdrawal withdrawal;

                        if (!psidechaintree->GetWithdrawal(id, withdrawal)) {
                            error("DisconnectBlock(): withdrawal of bundle not in ldb");
                            return DISCONNECT_FAILED;
                        }
                        if (withdrawal.status == WITHDRAWAL_UNSPENT) {
                            error("DisconnectBlock(): withdrawal of bundle has invalid unspent status");
                            return DISCONNECT_FAILED;
                        }

                        vWithdrawal.push_back(withdrawal);
                    }

                    // Update status of withdrawals(s)
                    for (size_t w = 0; w < vWithdrawal.size(); w++)
                        vWithdrawal[w].status = WITHDRAWAL_UNSPENT;

                    // Write to ldb

                    if (!psidechaintree->WriteWithdrawalUpdate(vWithdrawal)) {
                        error("DisconnectBlock(): Failed to write withdrawal update!");
                        return DISCONNECT_FAILED;
                    }

                    SidechainWithdrawalBundle withdrawalBundleUpdate = *withdrawalBundle;
                    withdrawalBundleUpdate.status = WITHDRAWAL_BUNDLE_FAILED;
                    if (!psidechaintree->WriteWithdrawalBundleUpdate(withdrawalBundleUpdate)) {
                        error("DisconnectBlock(): Failed to write withdrawal bundle update!");
                        return DISCONNECT_FAILED;
                    }
                }
            }

            // If this output is a withdrawal bundle status update commit - undo the update
            uint256 hashWithdrawalBundle;
            if (scriptPubKey.IsWithdrawalBundleFailCommit(hashWithdrawalBundle) ||
                    scriptPubKey.IsWithdrawalBundleSpentCommit(hashWithdrawalBundle)) {

                SidechainWithdrawalBundle withdrawalBundle;
                if (!psidechaintree->GetWithdrawalBundle(hashWithdrawalBundle, withdrawalBundle)) {
                    error("DisconnectBlock(): Failed to read withdrawal bundle to undo update!");
                    return DISCONNECT_FAILED;
                }

                withdrawalBundle.status = WITHDRAWAL_BUNDLE_CREATED;
                withdrawalBundle.nFailHeight = 0;

                if (!psidechaintree->WriteWithdrawalBundleUpdate(withdrawalBundle)) {
                    error("DisconnectBlock(): Failed to write withdrawal bundle undo update!");
                    return DISCONNECT_FAILED;
                }
            }

            // If output is a Withdrawal refund request set status back to Withdrawal_UNSPENT
            uint256 id;
            std::vector<unsigned char> vchSig;
            if (scriptPubKey.IsWithdrawalRefundRequest(id, vchSig)) {
                SidechainWithdrawal withdrawal;
                if (!psidechaintree->GetWithdrawal(id, withdrawal)) {
                    error("DisconnectBlock(): Failed to read Withdrawal for refund undo!");
                    return DISCONNECT_FAILED;
                }

                withdrawal.status = WITHDRAWAL_UNSPENT;
                if (!psidechaintree->WriteWithdrawalUpdate(std::vector<SidechainWithdrawal>{ withdrawal })) {
                    error("DisconnectBlock(): Failed to write Withdrawal refund update!");
                    return DISCONNECT_FAILED;
                }
            }
        }

        // restore inputs
        if (i > 0) { // not coinbases
            CTxUndo &txundo = blockUndo.vtxundo[i-1];
            if (txundo.vprevout.size() != tx.vin.size()) {
                error("DisconnectBlock(): transaction and undo data inconsistent");
                return DISCONNECT_FAILED;
            }
            for (unsigned int j = tx.vin.size(); j-- > 0;) {
                const COutPoint &out = tx.vin[j].prevout;
                int res = ApplyTxInUndo(std::move(txundo.vprevout[j]), view, out);
                if (res == DISCONNECT_FAILED) return DISCONNECT_FAILED;
                fClean = fClean && res != DISCONNECT_UNCLEAN;
            }
            // At this point, all of txundo.vprevout should have been moved out.
        }
    }

    // Revert the current withdrawal bundle hash
    psidechaintree->WriteLastWithdrawalBundleHash(pindex->pprev->hashWithdrawalBundle);

    // Step the side-DB markers back with the undo (only where the undo ran)
    if (fPoolUndo) {
        uint256 hashPoolBest;
        if (ppooltree->GetBestBlock(hashPoolBest) && !hashPoolBest.IsNull() &&
                !ppooltree->WriteBestBlock(pindex->pprev->GetBlockHash())) {
            error("DisconnectBlock(): Failed to step PoolDB best-block marker back!");
            return DISCONNECT_FAILED;
        }
    }
    if (fHouseUndo) {
        uint256 hashHouseBest;
        if (phousetree->GetBestBlock(hashHouseBest) && !hashHouseBest.IsNull() &&
                !phousetree->WriteBestBlock(pindex->pprev->GetBlockHash())) {
            error("DisconnectBlock(): Failed to step HouseDB best-block marker back!");
            return DISCONNECT_FAILED;
        }
    }
    if (fBillUndo) {
        uint256 hashBillBest;
        if (pbilltree->GetBestBlock(hashBillBest) && !hashBillBest.IsNull() &&
                !pbilltree->WriteBestBlock(pindex->pprev->GetBlockHash())) {
            error("DisconnectBlock(): Failed to step BillDB best-block marker back!");
            return DISCONNECT_FAILED;
        }
    }

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev->GetBlockHash());

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

void static FlushBlockFile(bool fFinalize = false)
{
    LOCK(cs_LastBlockFile);

    CDiskBlockPos posOld(nLastBlockFile, 0);

    FILE *fileOld = OpenBlockFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }

    fileOld = OpenUndoFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nUndoSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }
}

static bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize);

static bool WriteUndoDataForBlock(const CBlockUndo& blockundo, CValidationState& state, CBlockIndex* pindex, const CChainParams& chainparams)
{
    // Write undo information to disk
    if (pindex->GetUndoPos().IsNull()) {
        CDiskBlockPos _pos;
        if (!FindUndoPos(state, pindex->nFile, _pos, ::GetSerializeSize(blockundo, SER_DISK, CLIENT_VERSION) + 40))
            return error("ConnectBlock(): FindUndoPos failed");
        if (!UndoWriteToDisk(blockundo, _pos, pindex->pprev->GetBlockHash(), chainparams.MessageStart()))
            return AbortNode(state, "Failed to write undo data");

        // update nUndoPos in block index
        pindex->nUndoPos = _pos.nPos;
        pindex->nStatus |= BLOCK_HAVE_UNDO;
        setDirtyBlockIndex.insert(pindex);
    }

    return true;
}

static bool WriteTxIndexDataForBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex)
{
    if (!fTxIndex) return true;

    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(block.vtx.size());
    for (const CTransactionRef& tx : block.vtx)
    {
        vPos.push_back(std::make_pair(tx->GetHash(), pos));
        pos.nTxOffset += ::GetSerializeSize(*tx, SER_DISK, CLIENT_VERSION);
    }

    if (!pblocktree->WriteTxIndex(vPos)) {
        return AbortNode(state, "Failed to write transaction index");
    }

    return true;
}

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck() {
    RenameThread("bitcoin-scriptch");
    scriptcheckqueue.Thread();
}

// Protected by cs_main
VersionBitsCache versionbitscache;

int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    int32_t nVersion = VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        ThresholdState state = VersionBitsState(pindexPrev, params, static_cast<Consensus::DeploymentPos>(i), versionbitscache);
        if (state == THRESHOLD_LOCKED_IN || state == THRESHOLD_STARTED) {
            nVersion |= VersionBitsMask(params, static_cast<Consensus::DeploymentPos>(i));
        }
    }

    return nVersion;
}

/**
 * Threshold condition checker that triggers when unknown versionbits are seen on the network.
 */
class WarningBitsConditionChecker : public AbstractThresholdConditionChecker
{
private:
    int bit;

public:
    explicit WarningBitsConditionChecker(int bitIn) : bit(bitIn) {}

    int64_t BeginTime(const Consensus::Params& params) const override { return 0; }
    int64_t EndTime(const Consensus::Params& params) const override { return std::numeric_limits<int64_t>::max(); }
    int Period(const Consensus::Params& params) const override { return params.nMinerConfirmationWindow; }
    int Threshold(const Consensus::Params& params) const override { return params.nRuleChangeActivationThreshold; }

    bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const override
    {
        return ((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) &&
               ((pindex->nVersion >> bit) & 1) != 0 &&
               ((ComputeBlockVersion(pindex->pprev, params) >> bit) & 1) == 0;
    }
};

// Protected by cs_main
static ThresholdConditionCache warningcache[VERSIONBITS_NUM_BITS];

static unsigned int GetBlockScriptFlags(const CBlockIndex* pindex, const Consensus::Params& consensusparams) {
    AssertLockHeld(cs_main);

    unsigned int flags = SCRIPT_VERIFY_NONE;

    // Start enforcing P2SH (BIP16)
    if (pindex->nHeight >= consensusparams.BIP16Height) {
        flags |= SCRIPT_VERIFY_P2SH;
    }

    // Start enforcing the DERSIG (BIP66) rule
    if (pindex->nHeight >= consensusparams.BIP66Height) {
        flags |= SCRIPT_VERIFY_DERSIG;
    }

    // Start enforcing CHECKLOCKTIMEVERIFY (BIP65) rule
    if (pindex->nHeight >= consensusparams.BIP65Height) {
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // Start enforcing BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY) using versionbits logic.
    if (VersionBitsState(pindex->pprev, consensusparams, Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) {
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    }

    // Start enforcing WITNESS rules using versionbits logic.
    if (IsWitnessEnabled(pindex->pprev, consensusparams)) {
        flags |= SCRIPT_VERIFY_WITNESS;
        flags |= SCRIPT_VERIFY_NULLDUMMY;
    }

    return flags;
}



static int64_t nTimeCheck = 0;
static int64_t nTimeForks = 0;
static int64_t nTimeVerify = 0;
static int64_t nTimeConnect = 0;
static int64_t nTimeIndex = 0;
static int64_t nTimeCallbacks = 0;
static int64_t nTimeTotal = 0;
static int64_t nBlocksTotal = 0;

/** Apply the effects of this block (with given index) on the UTXO set represented by coins.
 *  Validity checks that depend on the UTXO set are also done; ConnectBlock()
 *  can fail if those validity checks fail (among other reasons). */
bool CChainState::ConnectBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams, bool fJustCheck, bool fCheckBMM, ConnectTrace* connectTrace)
{
    AssertLockHeld(cs_main);
    assert(pindex);
    // pindex->phashBlock can be null if called by CreateNewBlock/TestBlockValidity
    assert((pindex->phashBlock == nullptr) ||
           (*pindex->phashBlock == block.GetHash()));
    int64_t nTimeStart = GetTimeMicros();

    // Check it again in case a previous version let a bad block in
    // NOTE: We don't currently (re-)invoke ContextualCheckBlock() or
    // ContextualCheckBlockHeader() here. This means that if we add a new
    // consensus rule that is enforced in one of those two functions, then we
    // may have let in a block that violates the rule prior to updating the
    // software, and we would NOT be enforcing the rule here. Fully solving
    // upgrade from one software version to the next after a consensus rule
    // change is potentially tricky and issue-specific (see RewindBlockIndex()
    // for one general approach that was used for BIP 141 deployment).
    // Also, currently the rule against blocks more than 2 hours in the future
    // is enforced in ContextualCheckBlockHeader(); we wouldn't want to
    // re-enforce that rule here (at least until we make it impossible for
    // GetAdjustedTime() to go backward).
    if (!CheckBlock(block, state, chainparams.GetConsensus(), !fJustCheck /* fCheckMerkleRoot */, fCheckBMM))
        return error("%s: Consensus::CheckBlock: %s", __func__, FormatStateMessage(state));

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == nullptr ? uint256() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (block.GetHash() == chainparams.GetConsensus().hashGenesisBlock) {
        if (!fJustCheck)
            view.SetBestBlock(pindex->GetBlockHash());
        return true;
    }

    nBlocksTotal++;

    bool fScriptChecks = true;

    int64_t nTime1 = GetTimeMicros(); nTimeCheck += nTime1 - nTimeStart;
    LogPrint(BCLog::BENCH, "    - Sanity checks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime1 - nTimeStart), nTimeCheck * MICRO, nTimeCheck * MILLI / nBlocksTotal);

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied to all blocks with a timestamp after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes during their
    // initial block download.
    bool fEnforceBIP30 = (!pindex->phashBlock) || // Enforce on CreateNewBlock invocations which don't have a hash.
                          !((pindex->nHeight==91842 && pindex->GetBlockHash() == uint256S("0x00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")) ||
                           (pindex->nHeight==91880 && pindex->GetBlockHash() == uint256S("0x00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")));

    // Once BIP34 activated it was not possible to create new duplicate coinbases and thus other than starting
    // with the 2 existing duplicate coinbase pairs, not possible to create overwriting txs.  But by the
    // time BIP34 activated, in each of the existing pairs the duplicate coinbase had overwritten the first
    // before the first had been spent.  Since those coinbases are sufficiently buried its no longer possible to create further
    // duplicate transactions descending from the known pairs either.
    // If we're on the known chain at height greater than where BIP34 activated, we can save the db accesses needed for the BIP30 check.
    assert(pindex->pprev);
    CBlockIndex *pindexBIP34height = pindex->pprev->GetAncestor(chainparams.GetConsensus().BIP34Height);
    //Only continue to enforce if we're below BIP34 activation height or the block hash at that height doesn't correspond.
    fEnforceBIP30 = fEnforceBIP30 && (!pindexBIP34height || !(pindexBIP34height->GetBlockHash() == chainparams.GetConsensus().BIP34Hash));

    if (fEnforceBIP30) {
        for (const auto& tx : block.vtx) {
            for (size_t o = 0; o < tx->vout.size(); o++) {
                if (view.HaveCoin(COutPoint(tx->GetHash(), o))) {
                    return state.DoS(100, error("ConnectBlock(): tried to overwrite transaction"),
                                     REJECT_INVALID, "bad-txns-BIP30");
                }
            }
        }
    }

    // Start enforcing BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY) using versionbits logic.
    int nLockTimeFlags = 0;
    if (VersionBitsState(pindex->pprev, chainparams.GetConsensus(), Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) {
        nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE;
    }

    // Get the script flags for this block
    unsigned int flags = GetBlockScriptFlags(pindex, chainparams.GetConsensus());

    int64_t nTime2 = GetTimeMicros(); nTimeForks += nTime2 - nTime1;
    LogPrint(BCLog::BENCH, "    - Fork checks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime2 - nTime1), nTimeForks * MICRO, nTimeForks * MILLI / nBlocksTotal);

    CBlockUndo blockundo;

    CCheckQueueControl<CScriptCheck> control(fScriptChecks && nScriptCheckThreads ? &scriptcheckqueue : nullptr);

    std::vector<int> prevheights;
    CAmount nFees = 0;
    int nInputs = 0;
    int64_t nSigOpsCost = 0;
    blockundo.vtxundo.reserve(block.vtx.size() - 1);
    std::vector<PrecomputedTransactionData> txdata;
    txdata.reserve(block.vtx.size()); // Required so that pointers to individual PrecomputedTransactionData don't get invalidated
    CAmount nDepositPayout = 0;
    CAmount nRefundPayout = 0;
    std::multimap<std::pair<CScript, CAmount>, uint256> mapRefundOutputs;
    std::vector<SidechainWithdrawal> vRefundedWithdrawal;
    std::set<uint256> setRefundWithdrawalID;
    std::vector<BitAsset> vAsset;

    std::vector<CBill> vBillNew;                // bills issued in this block
    std::map<uint32_t, CBill> mapBillUpdate;    // pre-existing bills mutated in this block
    uint32_t nBillIDNext = 0;                   // lazily seeded from BillDB
    std::vector<CHouse> vHouseNew;              // houses registered in this block
    std::map<uint32_t, CHouse> mapHouseUpdate;  // pre-existing houses mutated in this block
    uint32_t nHouseIDNext = 0;                  // lazily seeded from HouseDB
    std::map<uint32_t, CPool> mapPoolUpdate;    // pools created or mutated in this block
    std::vector<uint32_t> vPoolRemove;          // pools RETIREd (deleted) this block
    std::set<uint32_t> setPoolTouched;          // ONE pool op per pool per block (decision 3)

    // Side-DB lifecycle (3.4 review): HouseDB/BillDB carry a best-block
    // marker written ATOMICALLY with each block's effects. Normally the
    // marker sits at the parent; if it is at THIS block or a descendant, the
    // effects are already in the DB (crash replay - the coins DB lagged the
    // side DBs) and the side-DB sections must be SKIPPED, not re-applied:
    // re-application double-counts (topups, nMintedUnits) and the ATTEST
    // priors check would reject the canonical chain outright. Any other
    // marker position is unhealable divergence - abort to -reindex rather
    // than fork off silently. fJustCheck never reaches the flush, and a
    // template builds on the tip (marker == parent), so the check is real-
    // connect only.
    bool fHouseDBReplay = false;
    bool fBillDBReplay = false;
    bool fPoolDBReplay = false;
    if (!fJustCheck) {
        const auto SideDBReplayStatus = [&](const uint256& hashSideBest, bool& fReplayOut) {
            fReplayOut = false;
            if (hashSideBest.IsNull())
                return true;                     // bootstrap: marker starts with the first flush
            if (pindex->pprev && hashSideBest == pindex->pprev->GetBlockHash())
                return true;                     // normal: DB is at the parent
            BlockMap::iterator it = mapBlockIndex.find(hashSideBest);
            if (it == mapBlockIndex.end())
                return false;                    // marker on an unknown block
            const CBlockIndex* pMarker = it->second;
            if (pMarker->nHeight >= pindex->nHeight && pMarker->GetAncestor(pindex->nHeight) == pindex) {
                fReplayOut = true;               // this block already applied
                return true;
            }
            return false;                        // diverged (other branch / behind with gaps)
        };
        uint256 hashHouseBest;
        phousetree->GetBestBlock(hashHouseBest);
        if (!SideDBReplayStatus(hashHouseBest, fHouseDBReplay))
            return AbortNode(state, "HouseDB is out of sync with the chain (crash damage?) - restart with -reindex");
        uint256 hashBillBest;
        pbilltree->GetBestBlock(hashBillBest);
        if (!SideDBReplayStatus(hashBillBest, fBillDBReplay))
            return AbortNode(state, "BillDB is out of sync with the chain (crash damage?) - restart with -reindex");
        uint256 hashPoolBest;
        ppooltree->GetBestBlock(hashPoolBest);
        if (!SideDBReplayStatus(hashPoolBest, fPoolDBReplay))
            return AbortNode(state, "PoolDB is out of sync with the chain (crash damage?) - restart with -reindex");
    }

    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const CTransaction &tx = *(block.vtx[i]);

        nInputs += tx.vin.size();

        // Find & verify refund request txns - verify coinbase payouts later
        for (const CTxOut& o : tx.vout) {
            const CScript& scriptPubKey = o.scriptPubKey;
            uint256 id;
            std::vector<unsigned char> vchSig;
            if (!scriptPubKey.IsWithdrawalRefundRequest(id, vchSig))
                continue;

            if (id.IsNull()) {
                return state.DoS(100, error("%s: Invalid Withdrawal refund!", __func__),
                            REJECT_INVALID, "verify-withdrawal-refund-no-script");
            }

            SidechainWithdrawal withdrawal;
            if (!VerifyWithdrawalRefundRequest(id, vchSig, withdrawal)) {
                return state.DoS(100, error("%s: Invalid Withdrawal refund!", __func__),
                            REJECT_INVALID, "verify-withdrawal-refund-invalid");
            }

            if (setRefundWithdrawalID.count(id)) {
                return state.DoS(100, error("%s: Invalid Withdrawal refund!", __func__),
                            REJECT_INVALID, "verify-withdrawal-refund-duplicate");
            }
            setRefundWithdrawalID.insert(id);

            // Keep track of refund request outputs so that we can verify they
            // each have a matching coinbase payout output later.
            CScript scriptDest = GetScriptForDestination(DecodeDestination(withdrawal.strRefundDestination));
            mapRefundOutputs.insert(std::pair<std::pair<CScript, CAmount>, uint256>( std::make_pair(scriptDest, withdrawal.amount), id));

            // Update withdrawal object status and keep track of it so that we can apply
            // the update later if all verification checks work out.
            withdrawal.status = WITHDRAWAL_SPENT;
            vRefundedWithdrawal.push_back(withdrawal);

            // Keep track of the total refunded Withdrawal amount for the block
            nRefundPayout += withdrawal.amount;
        }

        // Perform non coinbase txn checks
        CAmount nTxFeeBill = 0;
        if (!tx.IsCoinBase())
        {
            CAmount txfee = 0;
            if (!Consensus::CheckTxInputs(tx, state, view, pindex->nHeight, txfee)) {
                return error("%s: Consensus::CheckTxInputs: %s, %s", __func__, tx.GetHash().ToString(), FormatStateMessage(state));
            }
            nFees += txfee;
            nTxFeeBill = txfee;
            if (!MoneyRange(nFees)) {
                return state.DoS(100, error("%s: accumulated fee in the block out of range.", __func__),
                                 REJECT_INVALID, "bad-txns-accumulated-fee-outofrange");
            }

            // Check that transaction is BIP68 final
            // BIP68 lock checks (as opposed to nLockTime checks) must
            // be in ConnectBlock because they require the UTXO set
            prevheights.resize(tx.vin.size());
            for (size_t j = 0; j < tx.vin.size(); j++) {
                prevheights[j] = view.AccessCoin(tx.vin[j].prevout).nHeight;
            }

            if (!SequenceLocks(tx, nLockTimeFlags, &prevheights, *pindex)) {
                return state.DoS(100, error("%s: contains a non-BIP68-final transaction", __func__),
                                 REJECT_INVALID, "bad-txns-nonfinal");
            }
        }

        // Count deposit output amounts and collect deposits
        std::vector<SidechainDeposit> vDeposit;
        if (tx.IsCoinBase()) {
            for (const CTxOut& out : tx.vout) {
                const CScript& scriptPubKey = out.scriptPubKey;

                std::vector<unsigned char> vch;
                if (!scriptPubKey.IsSidechainObj(vch))
                    continue;

                SidechainObj *obj = ParseSidechainObj(vch);
                if (!obj) {
                    return state.DoS(90, error("%s: invalid sidechain obj script", __func__), REJECT_INVALID, "invalid-sidechain-obj-script");
                }

                if (obj->sidechainop != DB_SIDECHAIN_DEPOSIT_OP)
                    continue;

                const SidechainDeposit *deposit = (const SidechainDeposit *) obj;

                nDepositPayout += deposit->amtUserPayout;

                vDeposit.push_back(SidechainDeposit(deposit));

                delete obj;
            }
        }

        // Verify new deposit payouts
        //
        // - Find the previous deposit CTIP (input for first new deposit)
        //
        // - Re-calculate the deposit payouts ourselves
        //
        // - Loop through all of the rest of the deposits, recalculating
        // and verifying their deposit payout amounts
        //
        // - Check for a coinbase payout output matching each deposit
        //
        if (fCheckBMM && vDeposit.size()) {
            SidechainDeposit prev;
            bool fHaveDeposits = psidechaintree->GetLastDeposit(prev);

            CAmount amountPrev = CAmount(0);
            if (fHaveDeposits) {
                // First deposit should be spending current CTIP, find the
                // current CTIP in the deposit's inputs
                bool fFound = false;
                for (const CTxIn& in : vDeposit.front().dtx.vin) {
                    if (in.prevout.hash == prev.dtx.GetHash() &&
                            prev.dtx.vout.size() > in.prevout.n &&
                            prev.nBurnIndex == in.prevout.n) {
                        fFound = true;
                        break;
                    }
                }
                if (!fFound) {
                    return state.DoS(90, error("%s: invalid sidechain deposit input:\n%s", __func__, vDeposit.front().ToString()), REJECT_INVALID, "invalid-deposit-input");
                }
                // Copy the burn amount from CTIP
                amountPrev = prev.dtx.vout[prev.nBurnIndex].nValue;
            }

            // Check deposit payout amounts & find coinbase output
            for (const SidechainDeposit& d : vDeposit) {

                CAmount burn = d.dtx.vout[d.nBurnIndex].nValue;
                CAmount payout = burn - amountPrev;

                amountPrev = burn;

                if (d.amtUserPayout == 0 && d.strDest == SIDECHAIN_WITHDRAWAL_BUNDLE_RETURN_DEST)
                    continue;

                if (d.amtUserPayout != payout) {
                    return state.DoS(90, error("%s: invalid sidechain deposit amount:\n%s", __func__, d.ToString()), REJECT_INVALID, "invalid-deposit-amount");
                }

                // Now check coinbase outputs
                bool fFound = false;
                for (const CTxOut& o : block.vtx[0]->vout) {
                    if (o.nValue == d.amtUserPayout - SIDECHAIN_DEPOSIT_FEE &&
                            o.scriptPubKey == GetScriptForDestination(
                                DecodeDestination(d.strDest)))
                    {
                        fFound = true;
                        break;
                    }
                }
                if (!fFound) {
                    return state.DoS(90, error("%s: sidechain deposit missing output:\n%s", __func__, d.ToString()), REJECT_INVALID, "invalid-deposit-missing-output");
                }
            }
        }

        // GetTransactionSigOpCost counts 3 types of sigops:
        // * legacy (always)
        // * p2sh (when P2SH enabled in flags and excludes coinbase)
        // * witness (when witness enabled in flags and excludes coinbase)
        nSigOpsCost += GetTransactionSigOpCost(tx, view, flags);
        if (nSigOpsCost > MAX_BLOCK_SIGOPS_COST)
            return state.DoS(100, error("ConnectBlock(): too many sigops"),
                             REJECT_INVALID, "bad-blk-sigops");

        txdata.emplace_back(tx);
        if (!tx.IsCoinBase())
        {
            std::vector<CScriptCheck> vChecks;
            bool fCacheResults = fJustCheck; /* Don't cache results if we're actually connecting blocks (still consult the cache, though) */
            if (!CheckInputs(tx, state, view, fScriptChecks, flags, fCacheResults, fCacheResults, txdata[i], nScriptCheckThreads ? &vChecks : nullptr))
                return error("ConnectBlock(): CheckInputs on %s failed with %s",
                    tx.GetHash().ToString(), FormatStateMessage(state));
            control.Add(vChecks);
        }

        // New asset created - set asset ID # and update BitAssetDB
        uint32_t nNewAssetID = 0;
        if (tx.nVersion == TRANSACTION_BITASSET_CREATE_VERSION) {
            if (tx.vout.size() < 2) {
                return state.DoS(100, error("ConnectBlock(): Invalid BitAsset creation - vout too small"),
                                 REJECT_INVALID, "bad-asset-vout-small");
            }

            uint32_t nIDLast = 0;
            passettree->GetLastAssetID(nIDLast);

            BitAsset asset;
            asset.nID = nIDLast + 1;
            asset.strTicker = tx.ticker;
            asset.strHeadline = tx.headline;
            asset.payload = tx.payload;
            asset.txid = tx.GetHash();
            asset.nSupply = tx.vout[1].nValue;

            CTxDestination controllerDest;
            if (ExtractDestination(tx.vout[0].scriptPubKey, controllerDest)) {
                asset.strController = EncodeDestination(controllerDest);
            }
            else
            if (tx.vout[0].scriptPubKey.size() && tx.vout[0].scriptPubKey[0] == OP_RETURN) {
                asset.strController = "OP_RETURN";
            }
            else {
                return state.DoS(100, error("ConnectBlock(): Invalid BitAsset creation - controller destination invalid"),
                                 REJECT_INVALID, "bad-asset-controller-dest");
            }

            CTxDestination ownerDest;
            if (!ExtractDestination(tx.vout[1].scriptPubKey, ownerDest)) {
                    return state.DoS(100, error("ConnectBlock(): Invalid BitAsset creation - owner destination invalid"),
                                     REJECT_INVALID, "bad-asset-owner-dest");
            }
            asset.strOwner = EncodeDestination(ownerDest);

            vAsset.push_back(asset);

            // Update latest BitAsset ID #
            if (!fJustCheck && !passettree->WriteLastAssetID(asset.nID))
                return error("%s: Failed to update last BitAsset ID #!\n", __func__);

            // Copy new asset ID, we will pass it to CoinDB when we UpdateCoins
            nNewAssetID = asset.nID;
        }

        // Bill operations - validate against BillDB plus bills already
        // touched earlier in this block, and stage the resulting records
        uint32_t nNewBillID = 0;
        if (fBillDBReplay && tx.nVersion == TRANSACTION_BILL_VERSION) {
            // Crash replay: effects already in BillDB - recover the dense id
            // for coin tagging only (RollforwardBlock pattern)
            if (tx.nBillOp == BILL_OP_ISSUE) {
                BillIssue issue;
                if (DecodeBillPayload(tx.vchBillPayload, issue))
                    pbilltree->GetBillIDByHash(BillIDFromBody(issue.vchEncryptedBody), nNewBillID);
            } else if (tx.nBillOp == BILL_OP_ENDORSE) {
                BillEndorse endorse;
                if (DecodeBillPayload(tx.vchBillPayload, endorse))
                    nNewBillID = endorse.nBillID;
            }
        }
        else if (tx.nVersion == TRANSACTION_BILL_VERSION) {
            auto fnGetBill = [&](uint32_t nID, CBill& bill) {
                std::map<uint32_t, CBill>::const_iterator it = mapBillUpdate.find(nID);
                if (it != mapBillUpdate.end()) {
                    bill = it->second;
                    return true;
                }
                for (const CBill& b : vBillNew) {
                    if (b.nBillID == nID) {
                        bill = b;
                        return true;
                    }
                }
                return pbilltree->GetBill(nID, bill);
            };
            auto fnHaveBillHash = [&](const uint256& hash) {
                for (const CBill& b : vBillNew) {
                    if (b.billID == hash)
                        return true;
                }
                return pbilltree->HaveBillHash(hash);
            };

            CBill billResult;
            if (!CheckBillOperation(tx, state, pindex->nHeight, nTxFeeBill, fnGetBill, fnHaveBillHash, billResult))
                return error("ConnectBlock(): CheckBillOperation on %s failed with %s",
                    tx.GetHash().ToString(), FormatStateMessage(state));

            if (tx.nBillOp == BILL_OP_ISSUE) {
                if (nBillIDNext == 0) {
                    uint32_t nIDLast = 0;
                    pbilltree->GetLastBillID(nIDLast);
                    nBillIDNext = nIDLast + 1;
                }
                billResult.nBillID = nBillIDNext++;
                vBillNew.push_back(billResult);
                nNewBillID = billResult.nBillID;
            } else {
                bool fPendingNew = false;
                for (CBill& b : vBillNew) {
                    if (b.nBillID == billResult.nBillID) {
                        b = billResult;
                        fPendingNew = true;
                        break;
                    }
                }
                if (!fPendingNew)
                    mapBillUpdate[billResult.nBillID] = billResult;
            }
        }

        // House operations - validate against HouseDB plus houses already
        // touched in this block. Consensus rule: ONE house op per house per
        // block (keeps the WINDDOWN / tail undo deterministic).
        uint32_t nNewHouseID = 0;
        if (fHouseDBReplay && tx.nVersion == TRANSACTION_HOUSE_VERSION) {
            // Crash replay: effects already in HouseDB - recover the dense id
            // for coin tagging only (RollforwardBlock pattern)
            if (tx.nHouseOp == HOUSE_OP_REGISTER) {
                HouseRegister reg;
                if (DecodeHousePayload(tx.vchHousePayload, reg))
                    phousetree->GetHouseIDByHash(HouseIDFromDeclaration(reg), nNewHouseID);
            } else if (tx.nHouseOp == HOUSE_OP_TOPUP) {
                HouseTopup topup;
                if (DecodeHousePayload(tx.vchHousePayload, topup))
                    nNewHouseID = topup.nHouseID;
            } else if (tx.nHouseOp == HOUSE_OP_ADMIT) {
                HouseAdmit admit;
                if (DecodeHousePayload(tx.vchHousePayload, admit))
                    nNewHouseID = admit.nHouseID;
            } else if (tx.nHouseOp == HOUSE_OP_DEFER) {
                HouseDefer def;
                if (DecodeHousePayload(tx.vchHousePayload, def))
                    nNewHouseID = def.nHouseID;
            }
        }
        else if (tx.nVersion == TRANSACTION_HOUSE_VERSION) {
            auto fnGetHouse = [&](uint32_t nID, CHouse& house) {
                std::map<uint32_t, CHouse>::const_iterator it = mapHouseUpdate.find(nID);
                if (it != mapHouseUpdate.end()) {
                    house = it->second;
                    return true;
                }
                for (const CHouse& h : vHouseNew) {
                    if (h.nHouseID == nID) {
                        house = h;
                        return true;
                    }
                }
                return phousetree->GetHouse(nID, house);
            };
            auto fnHaveHouseHash = [&](const uint256& hash) {
                for (const CHouse& h : vHouseNew) {
                    if (h.houseID == hash)
                        return true;
                }
                return phousetree->HaveHouseHash(hash);
            };
            auto fnHaveClassID = [&](const std::string& strClassID) {
                for (const CHouse& h : vHouseNew) {
                    if (h.strClassID == strClassID)
                        return true;
                }
                return phousetree->HaveClassID(strClassID);
            };

            // ATTEST reserve proofs verify against the PARENT-chain state: a
            // coin spent by an EARLIER tx in this block was unspent at the
            // parent, so recover it from that tx's undo entry. This keeps
            // attestation validity order-independent within the block (no
            // feerate-ordering can invalidate a template) while any coin
            // already spent BEFORE this block stays a hard failure.
            auto fnGetProofCoin = [&](const COutPoint& out, Coin& coin) {
                const Coin& c = view.AccessCoin(out);
                if (!c.IsSpent()) {
                    coin = c;
                    return true;
                }
                for (size_t j = 1; j < i; j++) {
                    const CTransaction& btx = *(block.vtx[j]);
                    for (size_t k = 0; k < btx.vin.size(); k++) {
                        if (btx.vin[k].prevout == out) {
                            if (j - 1 < blockundo.vtxundo.size() &&
                                    k < blockundo.vtxundo[j - 1].vprevout.size()) {
                                coin = blockundo.vtxundo[j - 1].vprevout[k];
                                return true;
                            }
                            return false;
                        }
                    }
                }
                return false;
            };
            auto fnGetBlockHash = [&](uint32_t nH, uint256& hash) {
                if ((int64_t)nH >= (int64_t)pindex->nHeight)
                    return false;
                const CBlockIndex* pAsOf = pindex->GetAncestor((int)nH);
                if (!pAsOf)
                    return false;
                hash = pAsOf->GetBlockHash();
                return true;
            };

            CHouse houseResult;
            if (!CheckHouseOperation(tx, state, pindex->nHeight, fnGetHouse, fnHaveHouseHash, fnHaveClassID, fnGetProofCoin, fnGetBlockHash, houseResult))
                return error("ConnectBlock(): CheckHouseOperation on %s failed with %s",
                    tx.GetHash().ToString(), FormatStateMessage(state));

            if (tx.nHouseOp == HOUSE_OP_REGISTER) {
                if (nHouseIDNext == 0) {
                    uint32_t nIDLast = 0;
                    phousetree->GetLastHouseID(nIDLast);
                    nHouseIDNext = nIDLast + 1;
                }
                houseResult.nHouseID = nHouseIDNext++;
                vHouseNew.push_back(houseResult);
                nNewHouseID = houseResult.nHouseID;
            } else {
                // One op per house per block: a second mutation of a house
                // already staged (registered or updated this block) is invalid
                for (const CHouse& h : vHouseNew) {
                    if (h.nHouseID == houseResult.nHouseID)
                        return state.DoS(100, error("ConnectBlock(): second house op in block for house %u",
                            houseResult.nHouseID), REJECT_INVALID, "bad-house-multiple-ops");
                }
                if (mapHouseUpdate.count(houseResult.nHouseID))
                    return state.DoS(100, error("ConnectBlock(): second house op in block for house %u",
                        houseResult.nHouseID), REJECT_INVALID, "bad-house-multiple-ops");
                mapHouseUpdate[houseResult.nHouseID] = houseResult;

                // TOPUP / ADMIT / DEFER create a new escrow output that AddCoins
                // must tag - propagate the dense id (RollforwardBlock does the
                // same). Without this the escrow enters chainstate UNTAGGED
                // (anyone-can-spend + a connect-vs-replay consensus split).
                // DEFER's output is the locked till (3.5 D11); it is escrow
                // custody exactly like a pledge.
                if (tx.nHouseOp == HOUSE_OP_TOPUP || tx.nHouseOp == HOUSE_OP_ADMIT ||
                        tx.nHouseOp == HOUSE_OP_DEFER)
                    nNewHouseID = houseResult.nHouseID;
            }
        }

        // Note operations (Phase 3.2). MINT / REDEEM change house state
        // (nMintedUnits) and so ride the SAME one-op-per-house-per-block staging
        // as governance ops (mapHouseUpdate) - at most one house-state-changing
        // op per house per block, undone per-op in DisconnectBlock. TRANSFER
        // changes no house state (unlimited per block); its outputs are tagged
        // by AddCoins from the payload. Skipped on crash replay (effects
        // already in HouseDB; note coin tags are payload-self-contained).
        if (!fHouseDBReplay && tx.nVersion == TRANSACTION_NOTE_VERSION) {
            uint64_t nNoteUnitsIn = 0;
            for (const CTxIn& in : tx.vin) {
                const Coin& coin = view.AccessCoin(in.prevout);
                if (coin.fNote)
                    nNoteUnitsIn += coin.nNoteUnits;
            }
            auto fnGetHouse = [&](uint32_t nID, CHouse& house) {
                std::map<uint32_t, CHouse>::const_iterator it = mapHouseUpdate.find(nID);
                if (it != mapHouseUpdate.end()) { house = it->second; return true; }
                for (const CHouse& h : vHouseNew)
                    if (h.nHouseID == nID) { house = h; return true; }
                return phousetree->GetHouse(nID, house);
            };

            // Escrow / pot lookups against the block's running view: the
            // one-op-per-house rule means no other tx in this block can have
            // touched this house's escrow before us.
            auto fnGetCoin = [&](const COutPoint& out, Coin& coin) {
                const Coin& c = view.AccessCoin(out);
                if (c.IsSpent())
                    return false;
                coin = c;
                return true;
            };
            // The MINT reserve proof (R-i7) resolves against PARENT-CHAIN state,
            // recovering a coin spent by an EARLIER tx in THIS block from that
            // tx's undo entry - exactly the HOUSE_OP_ATTEST resolver. This keeps
            // mint validity order-independent within the block: a same-block (or
            // mempool) spend of a proven reserve coin the mint does not itself
            // spend cannot invalidate it, so no feerate ordering can turn a valid
            // template invalid (which would brick it - CreateNewBlock throws).
            auto fnGetProofCoin = [&](const COutPoint& out, Coin& coin) {
                const Coin& c = view.AccessCoin(out);
                if (!c.IsSpent()) {
                    coin = c;
                    return true;
                }
                for (size_t j = 1; j < i; j++) {
                    const CTransaction& btx = *(block.vtx[j]);
                    for (size_t k = 0; k < btx.vin.size(); k++) {
                        if (btx.vin[k].prevout == out) {
                            if (j - 1 < blockundo.vtxundo.size() &&
                                    k < blockundo.vtxundo[j - 1].vprevout.size()) {
                                coin = blockundo.vtxundo[j - 1].vprevout[k];
                                return true;
                            }
                            return false;
                        }
                    }
                }
                return false;
            };
            // Reserve-proof recency challenge resolves against the block being
            // connected (R-i7; matches the HOUSE_OP_ATTEST as-of resolver).
            auto fnGetBlockHash = [&](uint32_t nH, uint256& hash) {
                if ((int64_t)nH >= (int64_t)pindex->nHeight)
                    return false;
                const CBlockIndex* pAsOf = pindex->GetAncestor((int)nH);
                if (!pAsOf)
                    return false;
                hash = pAsOf->GetBlockHash();
                return true;
            };
            CHouse houseResult;
            bool fHouseChanged = false;
            if (!CheckNoteOperation(tx, state, pindex->nHeight, nNoteUnitsIn, fnGetHouse, fnGetCoin, fnGetProofCoin, fnGetBlockHash, houseResult, fHouseChanged))
                return error("ConnectBlock(): CheckNoteOperation on %s failed with %s",
                    tx.GetHash().ToString(), FormatStateMessage(state));

            if (fHouseChanged) {
                for (const CHouse& h : vHouseNew)
                    if (h.nHouseID == houseResult.nHouseID)
                        return state.DoS(100, error("ConnectBlock(): note op on house %u registered this block",
                            houseResult.nHouseID), REJECT_INVALID, "bad-house-multiple-ops");
                if (mapHouseUpdate.count(houseResult.nHouseID))
                    return state.DoS(100, error("ConnectBlock(): second house-state change for house %u this block",
                        houseResult.nHouseID), REJECT_INVALID, "bad-house-multiple-ops");
                mapHouseUpdate[houseResult.nHouseID] = houseResult;
            }
        }

        // Term-deposit ops (Phase 3.8). ORIGINATE/WITHDRAW/CLAIM change house
        // state (the D accounting) and take the one-house-state-change-per-block
        // slot, exactly like a note MINT; TRANSFER changes nothing. Deposits carry
        // no reserve proof (outside rho), so the resolver is the plain running
        // view (WITHDRAW/CLAIM read the receipt being spent, which is in the view).
        if (!fHouseDBReplay && tx.nVersion == TRANSACTION_DEPOSIT_VERSION) {
            auto fnGetHouse = [&](uint32_t nID, CHouse& house) {
                std::map<uint32_t, CHouse>::const_iterator it = mapHouseUpdate.find(nID);
                if (it != mapHouseUpdate.end()) { house = it->second; return true; }
                for (const CHouse& h : vHouseNew)
                    if (h.nHouseID == nID) { house = h; return true; }
                return phousetree->GetHouse(nID, house);
            };
            auto fnGetCoin = [&](const COutPoint& out, Coin& coin) {
                const Coin& c = view.AccessCoin(out);
                if (c.IsSpent())
                    return false;
                coin = c;
                return true;
            };
            CHouse houseResult;
            bool fHouseChanged = false;
            if (!CheckDepositOperation(tx, state, pindex->nHeight, fnGetHouse, fnGetCoin, houseResult, fHouseChanged))
                return error("ConnectBlock(): CheckDepositOperation on %s failed with %s",
                    tx.GetHash().ToString(), FormatStateMessage(state));

            if (fHouseChanged) {
                for (const CHouse& h : vHouseNew)
                    if (h.nHouseID == houseResult.nHouseID)
                        return state.DoS(100, error("ConnectBlock(): deposit op on house %u registered this block",
                            houseResult.nHouseID), REJECT_INVALID, "bad-house-multiple-ops");
                if (mapHouseUpdate.count(houseResult.nHouseID))
                    return state.DoS(100, error("ConnectBlock(): second house-state change for house %u this block",
                        houseResult.nHouseID), REJECT_INVALID, "bad-house-multiple-ops");
                mapHouseUpdate[houseResult.nHouseID] = houseResult;
            }
        }

        // Pool ops (Phase 3.7). Every op moves pool state; the priors-in-
        // payload discipline makes a second same-block op unconnectable, and
        // setPoolTouched enforces the rule explicitly (decision 3 - the
        // anti-sandwich property is consensus, not an accident of priors).
        // CREATE is house-status-dependent but house-state-neutral: it reads
        // the house (pending-aware) and takes NO house slot (the DEMAND model).
        if (tx.nVersion == TRANSACTION_POOL_VERSION) {
            // Crash window (RETIRE is the first op touching BOTH HouseDB and
            // PoolDB): houses flush BEFORE pools, so the only mid-flush window is
            // HouseDB already at this block (nMintedUnits burned) while PoolDB is
            // behind (pool still present). The house is already correct; just
            // delete the pool. Re-running CheckPoolOperation here would read the
            // already-burned house and could spuriously fail the liability gate,
            // so this is decode-only (the RollforwardBlock dense-id-recovery
            // pattern). PoolDB-ahead/HouseDB-behind cannot occur (pools last).
            if (fHouseDBReplay && !fPoolDBReplay && tx.nPoolOp == POOL_OP_RETIRE) {
                PoolRetire ret;
                if (!DecodePoolPayload(tx.vchPoolPayload, ret))
                    return state.DoS(100, error("ConnectBlock(): bad RETIRE payload on replay %s",
                        tx.GetHash().ToString()), REJECT_INVALID, "bad-pool-retire-payload");
                if (setPoolTouched.count(ret.nPoolID))
                    return state.DoS(100, error("ConnectBlock(): second pool op for pool %u this block",
                        ret.nPoolID), REJECT_INVALID, "bad-pool-multiple-ops");
                setPoolTouched.insert(ret.nPoolID);
                vPoolRemove.push_back(ret.nPoolID);
            }
            else if (!fPoolDBReplay) {
                auto fnGetPool = [&](uint32_t nID, CPool& pool) {
                    std::map<uint32_t, CPool>::const_iterator it = mapPoolUpdate.find(nID);
                    if (it != mapPoolUpdate.end()) { pool = it->second; return true; }
                    return ppooltree->GetPool(nID, pool);
                };
                auto fnGetHouse = [&](uint32_t nID, CHouse& house) {
                    std::map<uint32_t, CHouse>::const_iterator it = mapHouseUpdate.find(nID);
                    if (it != mapHouseUpdate.end()) { house = it->second; return true; }
                    for (const CHouse& h : vHouseNew)
                        if (h.nHouseID == nID) { house = h; return true; }
                    return phousetree->GetHouse(nID, house);
                };
                CPool poolResult;
                CHouse houseResult;
                bool fHouseChanged = false, fPoolRetired = false;
                if (!CheckPoolOperation(tx, state, pindex->nHeight, fnGetPool, fnGetHouse,
                        poolResult, houseResult, fHouseChanged, fPoolRetired))
                    return error("ConnectBlock(): CheckPoolOperation on %s failed with %s",
                        tx.GetHash().ToString(), FormatStateMessage(state));

                if (setPoolTouched.count(poolResult.nPoolID))
                    return state.DoS(100, error("ConnectBlock(): second pool op for pool %u this block",
                        poolResult.nPoolID), REJECT_INVALID, "bad-pool-multiple-ops");
                setPoolTouched.insert(poolResult.nPoolID);

                if (fPoolRetired) {
                    // Terminal: delete the record (NOT mapPoolUpdate). RETIRE also
                    // burns X from the house, so it takes the one-house-change slot
                    // too (deposit-op pattern) - a same-block MINT/ATTEST/deposit on
                    // the same house is rejected, which keeps the per-tx house undo
                    // order-insensitive. Pool ops run LAST in the block, so testing
                    // mapHouseUpdate/vHouseNew here catches every collision.
                    vPoolRemove.push_back(poolResult.nPoolID);
                    if (fHouseChanged && !fHouseDBReplay) {
                        for (const CHouse& h : vHouseNew)
                            if (h.nHouseID == houseResult.nHouseID)
                                return state.DoS(100, error("ConnectBlock(): pool retire on house %u registered this block",
                                    houseResult.nHouseID), REJECT_INVALID, "bad-house-multiple-ops");
                        if (mapHouseUpdate.count(houseResult.nHouseID))
                            return state.DoS(100, error("ConnectBlock(): second house-state change for house %u this block",
                                houseResult.nHouseID), REJECT_INVALID, "bad-house-multiple-ops");
                        mapHouseUpdate[houseResult.nHouseID] = houseResult;
                    }
                } else {
                    mapPoolUpdate[poolResult.nPoolID] = poolResult;
                }
            }
        }

        CTxUndo undoDummy;
        if (i > 0) {
            blockundo.vtxundo.push_back(CTxUndo());
        }

        CAmount amountAssetIn = CAmount(0);
        int nControlN = -1;
        uint32_t nAssetID = 0;
        UpdateCoins(tx, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pindex->nHeight, amountAssetIn, nControlN, nAssetID, nNewAssetID, nNewBillID, nNewHouseID);

        BitAssetTransactionData data;
        data.amountAssetIn = amountAssetIn;
        data.nControlN = nControlN;
        data.nAssetID = nNewAssetID ? nNewAssetID : nAssetID;
        data.txid = tx.GetHash();
        if (connectTrace && (amountAssetIn > 0 || tx.nVersion == TRANSACTION_BITASSET_CREATE_VERSION))
            connectTrace->SetBitAssetData(tx.GetHash(), data);
    }
    int64_t nTime3 = GetTimeMicros(); nTimeConnect += nTime3 - nTime2;
    LogPrint(BCLog::BENCH, "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs (%.2fms/blk)]\n", (unsigned)block.vtx.size(), MILLI * (nTime3 - nTime2), MILLI * (nTime3 - nTime2) / block.vtx.size(), nInputs <= 1 ? 0 : MILLI * (nTime3 - nTime2) / (nInputs-1), nTimeConnect * MICRO, nTimeConnect * MILLI / nBlocksTotal);

    // Verify Withdrawal refunds
    // - Check that for every Withdrawal refund request tx in the block a refund payout
    // of the correct amount to the Withdrawal refund address exists in the coinbase tx.
    //
    // - Check that no refund payout outputs exist that aren't based on a valid
    // refund request tx. This is checked by making sure that the coinbase total
    // out amount is nFees + nDepositPayout + nRefundPayout. Any extra outputs
    // will make the block invalid.
    //
    // Loop through the refund outputs in the multimap. For each key, get the
    // range of values with the same key (the refund destination script).
    // Make sure that the correct number of coinbase payout outputs exist for
    // each bucket of keys.
    for (auto it = mapRefundOutputs.begin(); it != mapRefundOutputs.end();)
    {
        // Get range of outputs with this CTxDestination
        std::pair<std::multimap<std::pair<CScript, CAmount>, uint256>::iterator, std::multimap<std::pair<CScript, CAmount>, uint256>::iterator> range;
        range = mapRefundOutputs.equal_range(it->first);

        // Count outputs that match items in the range
        int nOut = std::distance(range.first, range.second);
        int nFound = 0;
        for (const CTxOut& o : block.vtx[0]->vout) {
            if (o.scriptPubKey == it->first.first && o.nValue == it->first.second) {
                nFound++;

                // If we aren't looking for multiple outputs, stop now
                if (nOut == 1) {
                    break;
                }
            }
        }

        if (nFound != nOut)
            return state.DoS(100, error("%s: Invalid Withdrawal refund!", __func__),
                        REJECT_INVALID, "verify-withdrawal-refund-missing-payout");

        // Move on to end of range
        it = range.second;
    }

    // Update status of refunded Withdrawal(s)
    if (!fJustCheck && vRefundedWithdrawal.size()) {
        // Write the updated status of withdrawals(s) in the bundle (WITHDRAW_SPENT)
        if (!psidechaintree->WriteWithdrawalUpdate(vRefundedWithdrawal))
            return state.Error(strprintf("%s: Failed to write refunded withdrawal status update!\n", __func__));
    }

    CAmount blockReward = nFees + nDepositPayout + nRefundPayout;
    if (block.vtx[0]->GetValueOut() > blockReward)
        return state.DoS(100,
                         error("ConnectBlock(): coinbase pays too much (actual=%d vs limit=%d)",
                               block.vtx[0]->GetValueOut(), blockReward),
                               REJECT_INVALID, "bad-cb-amount");

    if (!control.Wait())
        return state.DoS(100, error("%s: CheckQueue failed", __func__), REJECT_INVALID, "block-validation-failed");
    int64_t nTime4 = GetTimeMicros(); nTimeVerify += nTime4 - nTime2;
    LogPrint(BCLog::BENCH, "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs (%.2fms/blk)]\n", nInputs - 1, MILLI * (nTime4 - nTime2), nInputs <= 1 ? 0 : MILLI * (nTime4 - nTime2) / (nInputs-1), nTimeVerify * MICRO, nTimeVerify * MILLI / nBlocksTotal);

    if (fJustCheck)
        return true;

    if (!WriteUndoDataForBlock(blockundo, state, pindex, chainparams))
        return false;

    if (!pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
        pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
        setDirtyBlockIndex.insert(pindex);
    }

    if (!WriteTxIndexDataForBlock(block, state, pindex))
        return false;

    if (fSidechainIndex) {
        SidechainClient client;

        // Send latest bundle to the mainchain if it hasn't been broadcasted yet
        SidechainWithdrawalBundle withdrawalBundleLatest;
        uint256 hashLatestWithdrawalBundle;
        psidechaintree->GetLastWithdrawalBundleHash(hashLatestWithdrawalBundle);
        if (psidechaintree->GetWithdrawalBundle(hashLatestWithdrawalBundle, withdrawalBundleLatest)) {
            // If we haven't broadcasted the latest bundle yet, do it now
            if (!bmmCache.HaveBroadcastedWithdrawalBundle(hashLatestWithdrawalBundle)) {
                std::string strHex = EncodeHexTx(withdrawalBundleLatest.tx);
                if (client.BroadcastWithdrawalBundle(strHex)) {
                    bmmCache.StoreBroadcastedWithdrawalBundle(hashLatestWithdrawalBundle);
                }
            }
        } else {
            LogPrintf("%s: Failed to get latest withdrawal bundle from ldb: %s!\n", __func__, hashLatestWithdrawalBundle.ToString());
        }

        // Check version commit in coinbase
        bool fVersionCommitFound = false;
        for (const CTxOut& out : block.vtx[0]->vout) {
            int32_t nVersion;
            if (out.scriptPubKey.IsBlockVersionCommit(nVersion)) {
                if (block.nVersion != nVersion) {
                    LogPrintf("%s: Invalid block version commit.\n", __func__);
                    return state.DoS(25, false, REJECT_INVALID, "bad-version-commit", false, "invalid version commit");
                }
                fVersionCommitFound = true;
                break;
            }
        }
        if (!fVersionCommitFound) {
            LogPrintf("%s: Missing block version commit!\n", __func__);
            return state.DoS(25, false, REJECT_INVALID, "no-version-commit", false, "Block version commit not found!");
        }

        // Check current bundle hash in header and coinbase
        if (!hashLatestWithdrawalBundle.IsNull()) {
            bool fWithdrawalBundleCommitFound = false;
            for (const CTxOut& out : block.vtx[0]->vout) {
                uint256 hashWithdrawalBundle;
                if (out.scriptPubKey.IsWithdrawalBundleHashCommit(hashWithdrawalBundle)) {
                    if (hashWithdrawalBundle != hashLatestWithdrawalBundle) {
                        LogPrintf("%s: Invalid withdrawal bundle hash commit: %s != %s\n", __func__, hashLatestWithdrawalBundle.ToString(), hashWithdrawalBundle.ToString());
                        return state.DoS(25, false, REJECT_INVALID, "bad-withdrawal-bundle-commit", false, "invalid withdrawal bundle hash commit");
                    }
                    fWithdrawalBundleCommitFound = true;
                    break;
                }
            }
            if (!fWithdrawalBundleCommitFound) {
                LogPrintf("%s: Missing Withdrawal Bundle hash commit!\n", __func__);
                return state.DoS(25, false, REJECT_INVALID, "no-withdrawal-bundle-commit", false, "Withdrawal Bundle hash commit not found!");
            }

            if (block.hashWithdrawalBundle != hashLatestWithdrawalBundle) {
                LogPrintf("%s: Invalid Withdrawal Bundle hash in block header!\n", __func__);
                return state.DoS(25, false, REJECT_INVALID, "bad-header-withdrawal-bundle-commit", false, "Withdrawal Bundle hash in header is invalid!");
            }
        }
        // Check for & validate Withdrawal Bundle status updates
        for (const CTxOut& txout : block.vtx[0]->vout) {
            const CScript& scriptPubKey = txout.scriptPubKey;

            uint256 hashWithdrawalBundle;
            bool fFailCommit = scriptPubKey.IsWithdrawalBundleFailCommit(hashWithdrawalBundle);

            if (fFailCommit || scriptPubKey.IsWithdrawalBundleSpentCommit(hashWithdrawalBundle)) {
                // Verify with the mainchain when we are also checking BMM
                if (fCheckBMM) {
                    bool fVerified = fFailCommit ?
                        client.HaveFailedWithdrawalBundle(hashWithdrawalBundle) :
                        client.HaveSpentWithdrawalBundle(hashWithdrawalBundle);

                    if (!fVerified)
                        return state.Error(strprintf("%s: Invalid Withdrawal Bundle update : %s - %s!\n",
                                    __func__, fFailCommit ? "Failed" : "Paid out",
                                    hashWithdrawalBundle.ToString()));
                }

                // Load the Withdrawal Bundle object from LDB if we need to and then write an
                // update with the new Withdrawal Bundle status. If the commit is for the
                // current Withdrawal Bundle (which it always should be in practice) we have
                // already loaded it.
                if (hashWithdrawalBundle == withdrawalBundleLatest.tx.GetHash()) {
                    withdrawalBundleLatest.status = fFailCommit ? WITHDRAWAL_BUNDLE_FAILED : WITHDRAWAL_BUNDLE_SPENT;

                    // Keep track of the height a Withdrawal Bundle was marked failed
                    if (fFailCommit)
                        withdrawalBundleLatest.nFailHeight = pindex->nHeight;

                    if (!psidechaintree->WriteWithdrawalBundleUpdate(withdrawalBundleLatest))
                        return state.Error(strprintf("%s: Failed to write Withdrawal Bundle update!\n", __func__));

                } else {
                    SidechainWithdrawalBundle withdrawalBundle;
                    if (!psidechaintree->GetWithdrawalBundle(hashWithdrawalBundle, withdrawalBundle))
                        return state.Error(strprintf("%s: Failed to read Withdrawal Bundle for update!\n", __func__));

                    withdrawalBundle.status = fFailCommit ? WITHDRAWAL_BUNDLE_FAILED : WITHDRAWAL_BUNDLE_SPENT;

                    // Keep track of the height a Withdrawal Bundle was marked failed
                    if (fFailCommit)
                        withdrawalBundleLatest.nFailHeight = pindex->nHeight;

                    if (!psidechaintree->WriteWithdrawalBundleUpdate(withdrawalBundle))
                        return state.Error(strprintf("%s: Failed to write Withdrawal Bundle update!\n", __func__));
                }
            }
        }

        // Collect & verify sidechain objects
        std::vector<std::pair<uint256, const SidechainObj *> > vSidechainObjects;
        bool fFoundWithdrawalBundle = false;
        for (const CTransactionRef& tx : block.vtx) {
            for (const CTxOut& txout : tx->vout) {
                const CScript& scriptPubKey = txout.scriptPubKey;

                std::vector<unsigned char> vch;
                if (!scriptPubKey.IsSidechainObj(vch))
                    continue;

                SidechainObj *obj = ParseSidechainObj(vch);
                if (!obj)
                    return state.Error("Invalid sidechain obj script");

                // TODO
                // Refactor. We are also loading SidechainWithdrawal later when
                // calculating the ID. Instead do it only once.

                // Check validity of withdrawals.
                if (obj->sidechainop == DB_SIDECHAIN_WITHDRAWAL_OP) {
                    const SidechainWithdrawal *withdrawal = (const SidechainWithdrawal *) obj;
                    // Verify that burn output actually exists
                    bool fBurnFound = false;
                    // TODO refactor: looping through vout again during a loop
                    // through vout... could be more efficient
                    for (const CTxOut& o : tx->vout) {
                        if (o.scriptPubKey.size()
                                && o.scriptPubKey[0] == OP_RETURN
                                && o.nValue == withdrawal->amount)
                        {
                            // Make sure that the burn amount & fee are valid
                            if (withdrawal->amount > 0 && withdrawal->mainchainFee > 0
                                    && withdrawal->amount > withdrawal->mainchainFee)
                                fBurnFound = true;
                        }
                    }
                    if (!fBurnFound) {
                        return state.Error("Invalid Withdrawal: invalid-withdrawal-missing-or-invalid-burn");
                    }
                }

                // If the object is a withdrawal we do not want the ID to change when
                // the withdrawal status is changed so that we can update the status
                // using the same ID in ldb.
                uint256 id;
                if (obj->sidechainop == DB_SIDECHAIN_WITHDRAWAL_OP) {
                    const SidechainWithdrawal *withdrawal = (const SidechainWithdrawal *) obj;
                    id = withdrawal->GetID();
                }
                else
                if (obj->sidechainop == DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP) {
                    // A block is invalid if it adds a new Withdrawal Bundle when the current
                    // Withdrawal Bundle status hasn't been updated to either WITHDRAWAL_BUNDLE_FAILED
                    // or WITHDRAWAL_BUNDLE_SPENT
                    if (!hashLatestWithdrawalBundle.IsNull()) {
                        if (withdrawalBundleLatest.status == WITHDRAWAL_BUNDLE_CREATED) {
                            return state.Error(strprintf("%s Invalid Withdrawal Bundle - current Withdrawal Bundle still pending!\n", __func__));
                        }
                    }

                    // If we find a Withdrawal Bundle we will call VerifyWithdrawalBundles later
                    fFoundWithdrawalBundle = true;

                    SidechainWithdrawalBundle *withdrawalBundle = (SidechainWithdrawalBundle *) obj;

                    // Insert block height
                    withdrawalBundle->nHeight = pindex->nHeight;

                    id = withdrawalBundle->GetID();
                    obj = (SidechainObj *) withdrawalBundle;

                    LogPrintf("%s: Found new Withdrawal Bundle: %s.\n", __func__, withdrawalBundle->tx.GetHash().ToString());
                }
                else
                if (obj->sidechainop == DB_SIDECHAIN_DEPOSIT_OP) {
                    const SidechainDeposit *deposit = (const SidechainDeposit *) obj;
                    id = deposit->GetID();
                }
                vSidechainObjects.push_back(std::make_pair(id, obj));
            }
        }

        // Handle Withdrawal Bundle verification & withdrawal status update
        if (fFoundWithdrawalBundle) {
            std::string strFail = "";
            std::vector<SidechainWithdrawal> vWithdrawal;
            uint256 hashWithdrawalBundle;
            uint256 hashWithdrawalBundleID;

            // This will also return a list of withdrawal(s) from the Withdrawal Bundle
            if (!VerifyWithdrawalBundles(strFail, pindex->nHeight, block.vtx, vWithdrawal, hashWithdrawalBundle, hashWithdrawalBundleID, fCheckBMM /* fReplicate */))
                return state.Error(strprintf("%s: Invalid Withdrawal Bundle! Error: %s", __func__, strFail));

            if (hashWithdrawalBundle.IsNull())
                return state.Error(strprintf("%s: hashWithdrawalBundle shouldn't be null if VerifyWithdrawalBundles passed!\n", __func__));

            // Write the updated status of withdrawals in the Withdrawal Bundle (Withdrawal_IN_WITHDRAWAL_BUNDLE)
            if (!psidechaintree->WriteWithdrawalUpdate(vWithdrawal))
                return state.Error(strprintf("%s: Failed to write withdrawal update!\n", __func__));
        }

        // Write sidechain objects to db
        if (vSidechainObjects.size()) {
            bool ret = psidechaintree->WriteSidechainIndex(vSidechainObjects);
            if (!ret)
                return state.Error("Failed to write sidechain index!");

            // Cleanup
            for (size_t i = 0; i < vSidechainObjects.size(); i++)
                delete vSidechainObjects[i].second;
        }
    }

    // Write asset objects to db
    if (vAsset.size()) {
        if (!passettree->WriteBitAssets(vAsset))
            return state.Error("Failed to write BitAsset index!");
    }

    // Flush this block's bill / house effects with the best-block marker in
    // one atomic batch per DB (3.4 review: ties the side DBs to the chain
    // lifecycle - see the fHouseDBReplay/fBillDBReplay logic above). The
    // marker advances on EVERY block, ops or not; on crash replay the DB is
    // already ahead and must not be touched.
    if (!fBillDBReplay) {
        std::vector<CBill> vBillWrite = vBillNew;
        for (const std::pair<const uint32_t, CBill>& p : mapBillUpdate)
            vBillWrite.push_back(p.second);
        const uint32_t nLastBillID = nBillIDNext - 1;
        if (!pbilltree->WriteBlockEffects(vBillWrite, vBillNew.size() ? &nLastBillID : nullptr, pindex->GetBlockHash()))
            return state.Error("Failed to write bill index!");
    }

    if (!fHouseDBReplay) {
        std::vector<CHouse> vHouseWrite = vHouseNew;
        for (const std::pair<const uint32_t, CHouse>& p : mapHouseUpdate)
            vHouseWrite.push_back(p.second);
        const uint32_t nLastHouseID = nHouseIDNext - 1;
        if (!phousetree->WriteBlockEffects(vHouseWrite, vHouseNew.size() ? &nLastHouseID : nullptr, pindex->GetBlockHash()))
            return state.Error("Failed to write house index!");
    }

    if (!fPoolDBReplay) {
        std::vector<CPool> vPoolWrite;
        for (const std::pair<const uint32_t, CPool>& p : mapPoolUpdate)
            vPoolWrite.push_back(p.second);
        if (!ppooltree->WriteBlockEffects(vPoolWrite, vPoolRemove, pindex->GetBlockHash()))
            return state.Error("Failed to write pool index!");
    }

    assert(pindex->phashBlock);
    // add this block to the view's block chain
    view.SetBestBlock(pindex->GetBlockHash());

    int64_t nTime5 = GetTimeMicros(); nTimeIndex += nTime5 - nTime4;
    LogPrint(BCLog::BENCH, "    - Index writing: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime5 - nTime4), nTimeIndex * MICRO, nTimeIndex * MILLI / nBlocksTotal);

    int64_t nTime6 = GetTimeMicros(); nTimeCallbacks += nTime6 - nTime5;
    LogPrint(BCLog::BENCH, "    - Callbacks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime6 - nTime5), nTimeCallbacks * MICRO, nTimeCallbacks * MILLI / nBlocksTotal);

    return true;
}

/**
 * Update the on-disk chain state.
 * The caches and indexes are flushed depending on the mode we're called with
 * if they're too large, if it's been a while since the last write,
 * or always and in all cases if we're in prune mode and are deleting files.
 */
bool static FlushStateToDisk(const CChainParams& chainparams, CValidationState &state, FlushStateMode mode, int nManualPruneHeight) {
    int64_t nMempoolUsage = mempool.DynamicMemoryUsage();
    LOCK(cs_main);
    static int64_t nLastWrite = 0;
    static int64_t nLastFlush = 0;
    static int64_t nLastSetChain = 0;
    std::set<int> setFilesToPrune;
    bool fFlushForPrune = false;
    bool fDoFullFlush = false;
    int64_t nNow = 0;
    try {
    {
        LOCK(cs_LastBlockFile);
        if (fPruneMode && (fCheckForPruning || nManualPruneHeight > 0) && !fReindex) {
            if (nManualPruneHeight > 0) {
                FindFilesToPruneManual(setFilesToPrune, nManualPruneHeight);
            } else {
                FindFilesToPrune(setFilesToPrune, chainparams.PruneAfterHeight());
                fCheckForPruning = false;
            }
            if (!setFilesToPrune.empty()) {
                fFlushForPrune = true;
                if (!fHavePruned) {
                    pblocktree->WriteFlag("prunedblockfiles", true);
                    fHavePruned = true;
                }
            }
        }
        nNow = GetTimeMicros();
        // Avoid writing/flushing immediately after startup.
        if (nLastWrite == 0) {
            nLastWrite = nNow;
        }
        if (nLastFlush == 0) {
            nLastFlush = nNow;
        }
        if (nLastSetChain == 0) {
            nLastSetChain = nNow;
        }
        int64_t nMempoolSizeMax = gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
        int64_t cacheSize = pcoinsTip->DynamicMemoryUsage();
        int64_t nTotalSpace = nCoinCacheUsage + std::max<int64_t>(nMempoolSizeMax - nMempoolUsage, 0);
        // The cache is large and we're within 10% and 10 MiB of the limit, but we have time now (not in the middle of a block processing).
        bool fCacheLarge = mode == FLUSH_STATE_PERIODIC && cacheSize > std::max((9 * nTotalSpace) / 10, nTotalSpace - MAX_BLOCK_COINSDB_USAGE * 1024 * 1024);
        // The cache is over the limit, we have to write now.
        bool fCacheCritical = mode == FLUSH_STATE_IF_NEEDED && cacheSize > nTotalSpace;
        // It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload after a crash.
        bool fPeriodicWrite = mode == FLUSH_STATE_PERIODIC && nNow > nLastWrite + (int64_t)DATABASE_WRITE_INTERVAL * 1000000;
        // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
        bool fPeriodicFlush = mode == FLUSH_STATE_PERIODIC && nNow > nLastFlush + (int64_t)DATABASE_FLUSH_INTERVAL * 1000000;
        // Combine all conditions that result in a full cache flush.
        fDoFullFlush = (mode == FLUSH_STATE_ALWAYS) || fCacheLarge || fCacheCritical || fPeriodicFlush || fFlushForPrune;
        // Write blocks and block index to disk.
        if (fDoFullFlush || fPeriodicWrite) {
            // Depend on nMinDiskSpace to ensure we can write block index
            if (!CheckDiskSpace(0))
                return state.Error("out of disk space");
            // First make sure all block and undo data is flushed to disk.
            FlushBlockFile();
            // Then update all block file information (which may refer to block and undo files).
            {
                std::vector<std::pair<int, const CBlockFileInfo*> > vFiles;
                vFiles.reserve(setDirtyFileInfo.size());
                for (std::set<int>::iterator it = setDirtyFileInfo.begin(); it != setDirtyFileInfo.end(); ) {
                    vFiles.push_back(std::make_pair(*it, &vinfoBlockFile[*it]));
                    setDirtyFileInfo.erase(it++);
                }
                std::vector<const CBlockIndex*> vBlocks;
                vBlocks.reserve(setDirtyBlockIndex.size());
                for (std::set<CBlockIndex*>::iterator it = setDirtyBlockIndex.begin(); it != setDirtyBlockIndex.end(); ) {
                    vBlocks.push_back(*it);
                    setDirtyBlockIndex.erase(it++);
                }
                if (!pblocktree->WriteBatchSync(vFiles, nLastBlockFile, vBlocks)) {
                    return AbortNode(state, "Failed to write to block index database");
                }
            }
            // Finally remove any pruned files
            if (fFlushForPrune)
                UnlinkPrunedFiles(setFilesToPrune);
            nLastWrite = nNow;
        }
        // Flush best chain related state. This can only be done if the blocks / block index write was also done.
        if (fDoFullFlush && !pcoinsTip->GetBestBlock().IsNull()) {
            // Typical Coin structures on disk are around 48 bytes in size.
            // Pushing a new one to the database can cause it to be written
            // twice (once in the log, and once in the tables). This is already
            // an overestimation, as most will delete an existing entry or
            // overwrite one. Still, use a conservative safety factor of 2.
            if (!CheckDiskSpace(48 * 2 * 2 * pcoinsTip->GetCacheSize()))
                return state.Error("out of disk space");
            // Flush the chainstate (which may refer to block index entries).
            if (!pcoinsTip->Flush())
                return AbortNode(state, "Failed to write to coin database");
            nLastFlush = nNow;
        }
    }
    if (fDoFullFlush || ((mode == FLUSH_STATE_ALWAYS || mode == FLUSH_STATE_PERIODIC) && nNow > nLastSetChain + (int64_t)DATABASE_WRITE_INTERVAL * 1000000)) {
        // Update best block in wallet (so we can detect restored wallets).
        GetMainSignals().SetBestChain(chainActive.GetLocator());
        nLastSetChain = nNow;
    }
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
    return true;
}

void FlushStateToDisk() {
    CValidationState state;
    const CChainParams& chainparams = Params();
    FlushStateToDisk(chainparams, state, FLUSH_STATE_ALWAYS);
}

void PruneAndFlush() {
    CValidationState state;
    fCheckForPruning = true;
    const CChainParams& chainparams = Params();
    FlushStateToDisk(chainparams, state, FLUSH_STATE_NONE);
}

static void DoWarning(const std::string& strWarning)
{
    static bool fWarned = false;
    SetMiscWarning(strWarning);
    if (!fWarned) {
        AlertNotify(strWarning);
        fWarned = true;
    }
}

/** Check warning conditions and do some notifications on new chain tip set. */
void static UpdateTip(const CBlockIndex *pindexNew, const CChainParams& chainParams) {
    // New best block
    mempool.AddTransactionsUpdated(1);

    cvBlockChange.notify_all();

    std::vector<std::string> warningMessages;
    if (!IsInitialBlockDownload())
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = pindexNew;
        for (int bit = 0; bit < VERSIONBITS_NUM_BITS; bit++) {
            WarningBitsConditionChecker checker(bit);
            ThresholdState state = checker.GetStateFor(pindex, chainParams.GetConsensus(), warningcache[bit]);
            if (state == THRESHOLD_ACTIVE || state == THRESHOLD_LOCKED_IN) {
                const std::string strWarning = strprintf(_("Warning: unknown new rules activated (versionbit %i)"), bit);
                if (state == THRESHOLD_ACTIVE) {
                    DoWarning(strWarning);
                } else {
                    warningMessages.push_back(strWarning);
                }
            }
        }
        // Check the version of the last 100 blocks to see if we need to upgrade:
        for (int i = 0; i < 100 && pindex != nullptr; i++)
        {
            int32_t nExpectedVersion = ComputeBlockVersion(pindex->pprev, chainParams.GetConsensus());
            if (pindex->nVersion > VERSIONBITS_LAST_OLD_BLOCK_VERSION && (pindex->nVersion & ~nExpectedVersion) != 0)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            warningMessages.push_back(strprintf(_("%d of last 100 blocks have unexpected version"), nUpgraded));
        if (nUpgraded > 100/2)
        {
            std::string strWarning = _("Warning: Unknown block versions being mined! It's possible unknown rules are in effect");
            // notify GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            DoWarning(strWarning);
        }
    }
    LogPrintf("%s: new best=%s height=%d version=0x%08x tx=%lu date='%s' progress=%f cache=%.1fMiB(%utxo)", __func__,
      pindexNew->GetBlockHash().ToString(), pindexNew->nHeight, pindexNew->nVersion,
      (unsigned long)pindexNew->nChainTx,
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexNew->GetBlockTime()),
      GuessVerificationProgress(chainParams.TxData(), pindexNew), pcoinsTip->DynamicMemoryUsage() * (1.0 / (1<<20)), pcoinsTip->GetCacheSize());
    if (!warningMessages.empty())
        LogPrintf(" warning='%s'", boost::algorithm::join(warningMessages, ", "));
    LogPrintf("\n");

}

/** Disconnect chainActive's tip.
  * After calling, the mempool will be in an inconsistent state, with
  * transactions from disconnected blocks being added to disconnectpool.  You
  * should make the mempool consistent again by calling UpdateMempoolForReorg.
  * with cs_main held.
  *
  * If disconnectpool is nullptr, then no disconnected transactions are added to
  * disconnectpool (note that the caller is responsible for mempool consistency
  * in any case).
  */
bool CChainState::DisconnectTip(CValidationState& state, const CChainParams& chainparams, DisconnectedBlockTransactions *disconnectpool)
{
    CBlockIndex *pindexDelete = chainActive.Tip();
    assert(pindexDelete);
    // Read block from disk.
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    CBlock& block = *pblock;
    if (!ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus()))
        return AbortNode(state, "Failed to read block");
    // Apply the block atomically to the chain state.
    int64_t nStart = GetTimeMicros();
    {
        CCoinsViewCache view(pcoinsTip.get());
        assert(view.GetBestBlock() == pindexDelete->GetBlockHash());
        if (DisconnectBlock(block, pindexDelete, view) != DISCONNECT_OK)
            return error("DisconnectTip(): DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString());
        bool flushed = view.Flush();
        assert(flushed);
    }
    LogPrint(BCLog::BENCH, "- Disconnect block: %.2fms\n", (GetTimeMicros() - nStart) * MILLI);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(chainparams, state, FLUSH_STATE_IF_NEEDED))
        return false;

    if (disconnectpool) {
        // Save transactions to re-add to mempool at end of reorg
        for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
            disconnectpool->addTransaction(*it);
        }
        while (disconnectpool->DynamicMemoryUsage() > MAX_DISCONNECTED_TX_POOL_SIZE * 1000) {
            // Drop the earliest entry, and remove its children from the mempool.
            auto it = disconnectpool->queuedTx.get<insertion_order>().begin();
            mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
            disconnectpool->removeEntry(it);
        }
    }

    chainActive.SetTip(pindexDelete->pprev);

    UpdateTip(pindexDelete->pprev, chainparams);
    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    GetMainSignals().BlockDisconnected(pblock);
    return true;
}

static int64_t nTimeReadFromDisk = 0;
static int64_t nTimeConnectTotal = 0;
static int64_t nTimeFlush = 0;
static int64_t nTimeChainState = 0;
static int64_t nTimePostConnect = 0;


/**
 * Connect a new block to chainActive. pblock is either nullptr or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 *
 * The block is added to connectTrace if connection succeeds.
 */
bool CChainState::ConnectTip(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexNew, const std::shared_ptr<const CBlock>& pblock, ConnectTrace& connectTrace, DisconnectedBlockTransactions &disconnectpool)
{
    assert(pindexNew->pprev == chainActive.Tip());
    // Read block from disk.
    int64_t nTime1 = GetTimeMicros();
    std::shared_ptr<const CBlock> pthisBlock;
    if (!pblock) {
        std::shared_ptr<CBlock> pblockNew = std::make_shared<CBlock>();
        if (!ReadBlockFromDisk(*pblockNew, pindexNew, chainparams.GetConsensus()))
            return AbortNode(state, "Failed to read block");
        pthisBlock = pblockNew;
    } else {
        pthisBlock = pblock;
    }
    const CBlock& blockConnecting = *pthisBlock;
    // Apply the block atomically to the chain state.
    int64_t nTime2 = GetTimeMicros(); nTimeReadFromDisk += nTime2 - nTime1;
    int64_t nTime3;
    LogPrint(BCLog::BENCH, "  - Load block from disk: %.2fms [%.2fs]\n", (nTime2 - nTime1) * MILLI, nTimeReadFromDisk * MICRO);
    {
        CCoinsViewCache view(pcoinsTip.get());
        bool rv = ConnectBlock(blockConnecting, state, pindexNew, view, chainparams, false, true, &connectTrace);
        GetMainSignals().BlockChecked(blockConnecting, state);
        if (!rv) {
            if (state.IsInvalid())
                InvalidBlockFound(pindexNew, state);
            return error("ConnectTip(): ConnectBlock %s failed. Reason: %s", pindexNew->GetBlockHash().ToString(), FormatStateMessage(state));
        }
        nTime3 = GetTimeMicros(); nTimeConnectTotal += nTime3 - nTime2;
        LogPrint(BCLog::BENCH, "  - Connect total: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime3 - nTime2) * MILLI, nTimeConnectTotal * MICRO, nTimeConnectTotal * MILLI / nBlocksTotal);
        bool flushed = view.Flush();
        assert(flushed);
    }
    int64_t nTime4 = GetTimeMicros(); nTimeFlush += nTime4 - nTime3;
    LogPrint(BCLog::BENCH, "  - Flush: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime4 - nTime3) * MILLI, nTimeFlush * MICRO, nTimeFlush * MILLI / nBlocksTotal);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(chainparams, state, FLUSH_STATE_IF_NEEDED))
        return false;
    int64_t nTime5 = GetTimeMicros(); nTimeChainState += nTime5 - nTime4;
    LogPrint(BCLog::BENCH, "  - Writing chainstate: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime5 - nTime4) * MILLI, nTimeChainState * MICRO, nTimeChainState * MILLI / nBlocksTotal);
    // Remove conflicting transactions from the mempool.;
    mempool.removeForBlock(blockConnecting.vtx, pindexNew->nHeight);
    disconnectpool.removeForBlock(blockConnecting.vtx);
    // Update chainActive & related variables.
    chainActive.SetTip(pindexNew);
    UpdateTip(pindexNew, chainparams);
    // Connecting a block can strand a pending house/note op WITHOUT any input
    // conflict: the height alone can cross a house's lazy Stressed/Insolvent
    // boundary, and a confirmed op can retire an approver or overtake an
    // attestation's priors. Sweep, or the next template bricks. Runs AFTER
    // SetTip: the sweep evaluates at chainActive.Height()+1, and one block of
    // slack at a boundary is a PERMANENT brick (a failed template means no
    // block, so no later sweep would ever run).
    EvictStaleHouseNoteOps();

    int64_t nTime6 = GetTimeMicros(); nTimePostConnect += nTime6 - nTime5; nTimeTotal += nTime6 - nTime1;
    LogPrint(BCLog::BENCH, "  - Connect postprocess: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime6 - nTime5) * MILLI, nTimePostConnect * MICRO, nTimePostConnect * MILLI / nBlocksTotal);
    LogPrint(BCLog::BENCH, "- Connect block: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime6 - nTime1) * MILLI, nTimeTotal * MICRO, nTimeTotal * MILLI / nBlocksTotal);

    connectTrace.BlockConnected(pindexNew, std::move(pthisBlock));
    return true;
}

/**
 * Return the tip of the chain with the most work in it, that isn't
 * known to be invalid (it's however far from certain to be valid).
 */
CBlockIndex* CChainState::FindMostWorkChain() {
    do {
        CBlockIndex *pindexNew = nullptr;

        // Find the best candidate header.
        {
            std::set<CBlockIndex*, CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexCandidates.rbegin();
            if (it == setBlockIndexCandidates.rend())
                return nullptr;
            pindexNew = *it;
        }

        // Check whether all blocks on the path between the currently active chain and the candidate are valid.
        // Just going until the active chain is an optimization, as we know all blocks in it are valid already.
        CBlockIndex *pindexTest = pindexNew;
        bool fInvalidAncestor = false;
        while (pindexTest && !chainActive.Contains(pindexTest)) {
            assert(pindexTest->nChainTx || pindexTest->nHeight == 0);

            // Pruned nodes may have entries in setBlockIndexCandidates for
            // which block files have been deleted.  Remove those as candidates
            // for the most work chain if we come across them; we can't switch
            // to a chain unless we have all the non-active-chain parent blocks.
            bool fFailedChain = pindexTest->nStatus & BLOCK_FAILED_MASK;
            bool fMissingData = !(pindexTest->nStatus & BLOCK_HAVE_DATA);
            if (fFailedChain || fMissingData) {
                // Candidate chain is not usable (either invalid or missing data)
                if (fFailedChain && (pindexBestInvalid == nullptr))
                    pindexBestInvalid = pindexNew;
                CBlockIndex *pindexFailed = pindexNew;
                // Remove the entire chain from the set.
                while (pindexTest != pindexFailed) {
                    if (fFailedChain) {
                        pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    } else if (fMissingData) {
                        // If we're missing data, then add back to mapBlocksUnlinked,
                        // so that if the block arrives in the future we can try adding
                        // to setBlockIndexCandidates again.
                        mapBlocksUnlinked.insert(std::make_pair(pindexFailed->pprev, pindexFailed));
                    }
                    setBlockIndexCandidates.erase(pindexFailed);
                    pindexFailed = pindexFailed->pprev;
                }
                setBlockIndexCandidates.erase(pindexTest);
                fInvalidAncestor = true;
                break;
            }
            pindexTest = pindexTest->pprev;
        }
        if (!fInvalidAncestor)
            return pindexNew;
    } while(true);
}

/** Delete all entries in setBlockIndexCandidates that are worse than the current tip. */
void CChainState::PruneBlockIndexCandidates() {
    // Note that we can't delete the current block itself, as we may need to return to it later in case a
    // reorganization to a better block fails.
    std::set<CBlockIndex*, CBlockIndexWorkComparator>::iterator it = setBlockIndexCandidates.begin();
    while (it != setBlockIndexCandidates.end() && setBlockIndexCandidates.value_comp()(*it, chainActive.Tip())) {
        setBlockIndexCandidates.erase(it++);
    }
    // Either the current tip or a successor of it we're working towards is left in setBlockIndexCandidates.
    assert(!setBlockIndexCandidates.empty());
}

/**
 * Try to make some progress towards making pindexMostWork the active block.
 * pblock is either nullptr or a pointer to a CBlock corresponding to pindexMostWork.
 */
bool CChainState::ActivateBestChainStep(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexMostWork, const std::shared_ptr<const CBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace)
{
    AssertLockHeld(cs_main);
    const CBlockIndex *pindexOldTip = chainActive.Tip();
    const CBlockIndex *pindexFork = chainActive.FindFork(pindexMostWork);

    // Disconnect active blocks which are no longer in the best chain.
    bool fBlocksDisconnected = false;
    DisconnectedBlockTransactions disconnectpool;
    while (chainActive.Tip() && chainActive.Tip() != pindexFork) {
        if (!DisconnectTip(state, chainparams, &disconnectpool)) {
            // This is likely a fatal error, but keep the mempool consistent,
            // just in case. Only remove from the mempool in this case.
            UpdateMempoolForReorg(disconnectpool, false);
            return false;
        }
        fBlocksDisconnected = true;
    }

    // Build list of new blocks to connect.
    std::vector<CBlockIndex*> vpindexToConnect;
    bool fContinue = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight != pindexMostWork->nHeight) {
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few blocks along the way.
        int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);
        vpindexToConnect.clear();
        vpindexToConnect.reserve(nTargetHeight - nHeight);
        CBlockIndex *pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight) {
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }
        nHeight = nTargetHeight;

        // Connect new blocks.
        for (CBlockIndex *pindexConnect : reverse_iterate(vpindexToConnect)) {
            if (!ConnectTip(state, chainparams, pindexConnect, pindexConnect == pindexMostWork ? pblock : std::shared_ptr<const CBlock>(), connectTrace, disconnectpool)) {
                if (state.IsInvalid()) {
                    // The block violates a consensus rule.
                    if (!state.CorruptionPossible())
                        InvalidChainFound(vpindexToConnect.back());
                    state = CValidationState();
                    fInvalidFound = true;
                    fContinue = false;
                    break;
                } else {
                    // A system error occurred (disk space, database error, ...).
                    // Make the mempool consistent with the current tip, just in case
                    // any observers try to use it before shutdown.
                    UpdateMempoolForReorg(disconnectpool, false);
                    return false;
                }
            } else {
                PruneBlockIndexCandidates();
                if (!pindexOldTip) {
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
    }

    if (fBlocksDisconnected) {
        // If any blocks were disconnected, disconnectpool may be non empty.  Add
        // any disconnected transactions back to the mempool.
        UpdateMempoolForReorg(disconnectpool, true);
    }
    mempool.check(pcoinsTip.get());

    // Callbacks/notifications for a new best chain.
    if (fInvalidFound)
        CheckForkWarningConditionsOnNewFork(vpindexToConnect.back());
    else
        CheckForkWarningConditions();

    return true;
}

static void NotifyHeaderTip() {
    bool fNotify = false;
    bool fInitialBlockDownload = false;
    static CBlockIndex* pindexHeaderOld = nullptr;
    CBlockIndex* pindexHeader = nullptr;
    {
        LOCK(cs_main);
        pindexHeader = pindexBestHeader;

        if (pindexHeader != pindexHeaderOld) {
            fNotify = true;
            fInitialBlockDownload = IsInitialBlockDownload();
            pindexHeaderOld = pindexHeader;
        }
    }
    // Send block tip changed notifications without cs_main
    if (fNotify) {
        uiInterface.NotifyHeaderTip(fInitialBlockDownload, pindexHeader);
    }
}

/**
 * Make the best chain active, in multiple steps. The result is either failure
 * or an activated best chain. pblock is either nullptr or a pointer to a block
 * that is already loaded (to avoid loading it again from disk).
 */
bool CChainState::ActivateBestChain(CValidationState &state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock) {
    // Note that while we're often called here from ProcessNewBlock, this is
    // far from a guarantee. Things in the P2P/RPC will often end up calling
    // us in the middle of ProcessNewBlock - do not assume pblock is set
    // sanely for performance or correctness!
    AssertLockNotHeld(cs_main);

    CBlockIndex *pindexMostWork = nullptr;
    CBlockIndex *pindexNewTip = nullptr;
    int nStopAtHeight = gArgs.GetArg("-stopatheight", DEFAULT_STOPATHEIGHT);
    do {
        boost::this_thread::interruption_point();

        if (GetMainSignals().CallbacksPending() > 10) {
            // Block until the validation queue drains. This should largely
            // never happen in normal operation, however may happen during
            // reindex, causing memory blowup if we run too far ahead.
            SyncWithValidationInterfaceQueue();
        }

        const CBlockIndex *pindexFork;
        bool fInitialDownload;
        {
            LOCK(cs_main);
            ConnectTrace connectTrace(mempool); // Destructed before cs_main is unlocked

            CBlockIndex *pindexOldTip = chainActive.Tip();
            if (pindexMostWork == nullptr) {
                pindexMostWork = FindMostWorkChain();
            }

            // Whether we have anything to do at all.
            if (pindexMostWork == nullptr || pindexMostWork == chainActive.Tip())
                return true;

            bool fInvalidFound = false;
            std::shared_ptr<const CBlock> nullBlockPtr;
            if (!ActivateBestChainStep(state, chainparams, pindexMostWork, pblock && pblock->GetHash() == pindexMostWork->GetBlockHash() ? pblock : nullBlockPtr, fInvalidFound, connectTrace))
                return false;

            if (fInvalidFound) {
                // Wipe cache, we may need another branch now.
                pindexMostWork = nullptr;
            }
            pindexNewTip = chainActive.Tip();
            pindexFork = chainActive.FindFork(pindexOldTip);
            fInitialDownload = IsInitialBlockDownload();

            for (const PerBlockConnectTrace& trace : connectTrace.GetBlocksConnected()) {
                assert(trace.pblock && trace.pindex);
                GetMainSignals().BlockConnected(trace.mapAssetData, trace.pblock, trace.pindex, trace.conflictedTxs);
            }
        }
        // When we reach this point, we switched to a new tip (stored in pindexNewTip).

        // Notifications/callbacks that can run without cs_main

        // Notify external listeners about the new tip.
        GetMainSignals().UpdatedBlockTip(pindexNewTip, pindexFork, fInitialDownload);

        // Always notify the UI if a new block tip was connected
        if (pindexFork != pindexNewTip) {
            uiInterface.NotifyBlockTip(fInitialDownload, pindexNewTip);
        }

        if (nStopAtHeight && pindexNewTip && pindexNewTip->nHeight >= nStopAtHeight) StartShutdown();

        // We check shutdown only after giving ActivateBestChainStep a chance to run once so that we
        // never shutdown before connecting the genesis block during LoadChainTip(). Previously this
        // caused an assert() failure during shutdown in such cases as the UTXO DB flushing checks
        // that the best block hash is non-null.
        if (ShutdownRequested())
            break;
    } while (pindexNewTip != pindexMostWork);
    CheckBlockIndex(chainparams.GetConsensus());

    // Write changes periodically to disk, after relay.
    if (!FlushStateToDisk(chainparams, state, FLUSH_STATE_PERIODIC)) {
        return false;
    }

    return true;
}
bool ActivateBestChain(CValidationState &state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock) {
    return g_chainstate.ActivateBestChain(state, chainparams, std::move(pblock));
}

bool CChainState::PreciousBlock(CValidationState& state, const CChainParams& params, CBlockIndex *pindex)
{
    return ActivateBestChain(state, params, std::shared_ptr<const CBlock>());
}
bool PreciousBlock(CValidationState& state, const CChainParams& params, CBlockIndex *pindex) {
    return g_chainstate.PreciousBlock(state, params, pindex);
}

bool CChainState::InvalidateBlock(CValidationState& state, const CChainParams& chainparams, CBlockIndex *pindex)
{
    AssertLockHeld(cs_main);

    // We first disconnect backwards and then mark the blocks as invalid.
    // This prevents a case where pruned nodes may fail to invalidateblock
    // and be left unable to start as they have no tip candidates (as there
    // are no blocks that meet the "have data and are not invalid per
    // nStatus" criteria for inclusion in setBlockIndexCandidates).

    bool pindex_was_in_chain = false;
    CBlockIndex *invalid_walk_tip = chainActive.Tip();

    DisconnectedBlockTransactions disconnectpool;
    while (chainActive.Contains(pindex)) {
        pindex_was_in_chain = true;
        // ActivateBestChain considers blocks already in chainActive
        // unconditionally valid already, so force disconnect away from it.
        if (!DisconnectTip(state, chainparams, &disconnectpool)) {
            // It's probably hopeless to try to make the mempool consistent
            // here if DisconnectTip failed, but we can try.
            UpdateMempoolForReorg(disconnectpool, false);
            return false;
        }
    }

    // Now mark the blocks we just disconnected as descendants invalid
    // (note this may not be all descendants).
    while (pindex_was_in_chain && invalid_walk_tip != pindex) {
        invalid_walk_tip->nStatus |= BLOCK_FAILED_CHILD;
        setDirtyBlockIndex.insert(invalid_walk_tip);
        setBlockIndexCandidates.erase(invalid_walk_tip);
        invalid_walk_tip = invalid_walk_tip->pprev;
    }

    // Mark the block itself as invalid.
    pindex->nStatus |= BLOCK_FAILED_VALID;
    setDirtyBlockIndex.insert(pindex);
    setBlockIndexCandidates.erase(pindex);
    g_failed_blocks.insert(pindex);

    // DisconnectTip will add transactions to disconnectpool; try to add these
    // back to the mempool.
    UpdateMempoolForReorg(disconnectpool, true);

    // The resulting new best tip may not be in setBlockIndexCandidates anymore, so
    // add it again.
    BlockMap::iterator it = mapBlockIndex.begin();
    while (it != mapBlockIndex.end()) {
        if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx && !setBlockIndexCandidates.value_comp()(it->second, chainActive.Tip())) {
            setBlockIndexCandidates.insert(it->second);
        }
        it++;
    }

    InvalidChainFound(pindex);
    uiInterface.NotifyBlockTip(IsInitialBlockDownload(), pindex->pprev);
    return true;
}
bool InvalidateBlock(CValidationState& state, const CChainParams& chainparams, CBlockIndex *pindex) {
    return g_chainstate.InvalidateBlock(state, chainparams, pindex);
}

bool CChainState::ResetBlockFailureFlags(CBlockIndex *pindex) {
    AssertLockHeld(cs_main);

    int nHeight = pindex->nHeight;

    // Remove the invalidity flag from this block and all its descendants.
    BlockMap::iterator it = mapBlockIndex.begin();
    while (it != mapBlockIndex.end()) {
        if (!it->second->IsValid() && it->second->GetAncestor(nHeight) == pindex) {
            it->second->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(it->second);
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx && setBlockIndexCandidates.value_comp()(chainActive.Tip(), it->second)) {
                setBlockIndexCandidates.insert(it->second);
            }
            if (it->second == pindexBestInvalid) {
                // Reset invalid block marker if it was pointing to one of those.
                pindexBestInvalid = nullptr;
            }
            g_failed_blocks.erase(it->second);
        }
        it++;
    }

    // Remove the invalidity flag from all ancestors too.
    while (pindex != nullptr) {
        if (pindex->nStatus & BLOCK_FAILED_MASK) {
            pindex->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(pindex);
        }
        pindex = pindex->pprev;
    }
    return true;
}
bool ResetBlockFailureFlags(CBlockIndex *pindex) {
    return g_chainstate.ResetBlockFailureFlags(pindex);
}

CBlockIndex* CChainState::AddToBlockIndex(const CBlockHeader& block)
{
    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end())
        return it->second;

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(block);

    // Add mainchain block hash to index
    uint256 hashMainBlock = block.hashMainchainBlock;
    pindexNew->hashMainBlock = hashMainBlock;

    // We assign the sequence id to blocks only when the full data is available,
    // to avoid miners withholding blocks but broadcasting headers, to get a
    // competitive advantage.
    pindexNew->nSequenceId = 0;
    BlockMap::iterator mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    BlockMap::iterator miPrev = mapBlockIndex.find(block.hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
        pindexNew->BuildSkip();
    }
    pindexNew->nTimeMax = (pindexNew->pprev ? std::max(pindexNew->pprev->nTimeMax, pindexNew->nTime) : pindexNew->nTime);
    pindexNew->RaiseValidity(BLOCK_VALID_TREE);
    if (pindexBestHeader == nullptr || pindexBestHeader->nHeight < pindexNew->nHeight)
        pindexBestHeader = pindexNew;

    // Add to index of blocks tracked by their mainchain commitment block hash
    mapBlockMainHashIndex[hashMainBlock] = pindexNew;

    setDirtyBlockIndex.insert(pindexNew);

    return pindexNew;
}

/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */
bool CChainState::ReceivedBlockTransactions(const CBlock &block, CValidationState& state, CBlockIndex *pindexNew, const CDiskBlockPos& pos, const Consensus::Params& consensusParams)
{
    pindexNew->nTx = block.vtx.size();
    pindexNew->nChainTx = 0;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus |= BLOCK_HAVE_DATA;
    if (IsWitnessEnabled(pindexNew->pprev, consensusParams)) {
        pindexNew->nStatus |= BLOCK_OPT_WITNESS;
    }
    pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    setDirtyBlockIndex.insert(pindexNew);

    if (pindexNew->pprev == nullptr || pindexNew->pprev->nChainTx) {
        // If pindexNew is the genesis block or all parents are BLOCK_VALID_TRANSACTIONS.
        std::deque<CBlockIndex*> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant blocks that now may be eligible to be connected.
        while (!queue.empty()) {
            CBlockIndex *pindex = queue.front();
            queue.pop_front();
            pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;
            {
                LOCK(cs_nBlockSequenceId);
                pindex->nSequenceId = nBlockSequenceId++;
            }
            if (chainActive.Tip() == nullptr || !setBlockIndexCandidates.value_comp()(pindex, chainActive.Tip())) {
                setBlockIndexCandidates.insert(pindex);
            }
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pindex);
            while (range.first != range.second) {
                std::multimap<CBlockIndex*, CBlockIndex*>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                mapBlocksUnlinked.erase(it);
            }
        }
    } else {
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BLOCK_VALID_TREE)) {
            mapBlocksUnlinked.insert(std::make_pair(pindexNew->pprev, pindexNew));
        }
    }

    return true;
}

static bool FindBlockPos(CDiskBlockPos &pos, unsigned int nAddSize, unsigned int nHeight, uint64_t nTime, bool fKnown = false)
{
    LOCK(cs_LastBlockFile);

    unsigned int nFile = fKnown ? pos.nFile : nLastBlockFile;
    if (vinfoBlockFile.size() <= nFile) {
        vinfoBlockFile.resize(nFile + 1);
    }

    if (!fKnown) {
        while (vinfoBlockFile[nFile].nSize + nAddSize >= MAX_BLOCKFILE_SIZE) {
            nFile++;
            if (vinfoBlockFile.size() <= nFile) {
                vinfoBlockFile.resize(nFile + 1);
            }
        }
        pos.nFile = nFile;
        pos.nPos = vinfoBlockFile[nFile].nSize;
    }

    if ((int)nFile != nLastBlockFile) {
        if (!fKnown) {
            LogPrintf("Leaving block file %i: %s\n", nLastBlockFile, vinfoBlockFile[nLastBlockFile].ToString());
        }
        FlushBlockFile(!fKnown);
        nLastBlockFile = nFile;
    }

    vinfoBlockFile[nFile].AddBlock(nHeight, nTime);
    if (fKnown)
        vinfoBlockFile[nFile].nSize = std::max(pos.nPos + nAddSize, vinfoBlockFile[nFile].nSize);
    else
        vinfoBlockFile[nFile].nSize += nAddSize;

    if (!fKnown) {
        unsigned int nOldChunks = (pos.nPos + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        unsigned int nNewChunks = (vinfoBlockFile[nFile].nSize + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        if (nNewChunks > nOldChunks) {
            if (fPruneMode)
                fCheckForPruning = true;
            if (CheckDiskSpace(nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos)) {
                FILE *file = OpenBlockFile(pos);
                if (file) {
                    LogPrintf("Pre-allocating up to position 0x%x in blk%05u.dat\n", nNewChunks * BLOCKFILE_CHUNK_SIZE, pos.nFile);
                    AllocateFileRange(file, pos.nPos, nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos);
                    fclose(file);
                }
            }
            else
                return error("out of disk space");
        }
    }

    setDirtyFileInfo.insert(nFile);
    return true;
}

static bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize)
{
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    unsigned int nNewSize;
    pos.nPos = vinfoBlockFile[nFile].nUndoSize;
    nNewSize = vinfoBlockFile[nFile].nUndoSize += nAddSize;
    setDirtyFileInfo.insert(nFile);

    unsigned int nOldChunks = (pos.nPos + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    unsigned int nNewChunks = (nNewSize + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    if (nNewChunks > nOldChunks) {
        if (fPruneMode)
            fCheckForPruning = true;
        if (CheckDiskSpace(nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos)) {
            FILE *file = OpenUndoFile(pos);
            if (file) {
                LogPrintf("Pre-allocating up to position 0x%x in rev%05u.dat\n", nNewChunks * UNDOFILE_CHUNK_SIZE, pos.nFile);
                AllocateFileRange(file, pos.nPos, nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos);
                fclose(file);
            }
        }
        else
            return state.Error("out of disk space");
    }

    return true;
}

bool CheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckMerkleRoot, bool fCheckBMM)
{
    // These are checks that are independent of context.

    bool fGenesis = (block.GetHash() == Params().GetConsensus().hashGenesisBlock);

    // Check for mainchain connection
    if (!fGenesis && fCheckBMM && !CheckMainchainConnection()) {
        SetNetworkActive(false, "Failed to connect to mainchain when checking block!");
        return false;
    }

    if (block.fChecked)
        return true;

    // Check the merkle root.
    if (fCheckMerkleRoot) {
        bool mutated;
        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.DoS(100, false, REJECT_INVALID, "bad-txnmrklroot", true, "hashMerkleRoot mismatch");

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-duplicate", true, "duplicate transaction");
    }
    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.
    // Note that witness malleability is checked in ContextualCheckBlock, so no
    // checks that use witness data may be performed here.

    // Size limits
    if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-length", false, "size limits failed");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false, "first tx is not coinbase");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-multiple", false, "more than one coinbase");

    // Verify BMM with mainchain
    if (fCheckBMM && !VerifyBMM(block))
        return state.DoS(1, false, REJECT_INVALID, "bad-bmm", true, "invalid bmm / failed to verify BMM for block");

    if (!fGenesis && fCheckBMM) {
        // Check required PrevBlockCommit
        bool fPrevCommitFound = false;
        for (const CTxOut& out : block.vtx[0]->vout) {
            uint256 hashPrevMain;
            uint256 hashPrevSide;
            if (out.scriptPubKey.IsPrevBlockCommit(hashPrevMain, hashPrevSide)) {
                if (hashPrevMain != bmmCache.GetMainPrevBlockHash(block.hashMainchainBlock)) {
                    LogPrintf("%s: Invalid mainchain prevBlock commit: %s != %s\n", __func__, hashPrevMain.ToString(), bmmCache.GetMainPrevBlockHash(block.hashMainchainBlock).ToString());
                    return state.DoS(25, false, REJECT_INVALID, "bad-mc-prev", false, "invalid mainchin prevBlock commit");
                }
                if (hashPrevSide != block.hashPrevBlock) {
                    LogPrintf("%s: Invalid sidechain prevBlock commit: %s != %s\n", __func__, hashPrevSide.ToString(), block.hashPrevBlock.ToString());
                    return state.DoS(25, false, REJECT_INVALID, "bad-sc-prev", false, "invalid sidechain prevBlock commit");
                }
                fPrevCommitFound = true;
                break;
            }
        }
        if (!fPrevCommitFound) {
            LogPrintf("%s: Missing prevBlock commit!\n", __func__);
            return state.DoS(100, false, REJECT_INVALID, "no-prev-commit", false, "PrevBlockCommit not found!");
        }
    }

    // Find deposits and verify that they exist with mainchain
    if (fCheckBMM) {
        for (const CTxOut& out : block.vtx[0]->vout) {
            const CScript& scriptPubKey = out.scriptPubKey;

            std::vector<unsigned char> vch;
            if (!scriptPubKey.IsSidechainObj(vch))
                continue;

            SidechainObj *obj = ParseSidechainObj(vch);
            if (!obj) {
                return state.DoS(90, error("%s: invalid sidechain deposit obj script", __func__), REJECT_INVALID, "invalid-sidechain-obj-script");
            }

            if (obj->sidechainop != DB_SIDECHAIN_DEPOSIT_OP)
                continue;

            const SidechainDeposit* deposit = (const SidechainDeposit *) obj;

            if (!VerifyDeposit(deposit->hashMainchainBlock, deposit->dtx.GetHash(), deposit->nTx)) {
                delete obj;
                return state.DoS(1, error("%s: invalid sidechain deposit", __func__), REJECT_INVALID, "invalid-sidechain-deposit");
            }

            delete obj;
        }
    }

    // Check transactions
    for (const auto& tx : block.vtx)
        if (!CheckTransaction(*tx, state, true))
            return state.Invalid(false, state.GetRejectCode(), state.GetRejectReason(),
                                 strprintf("Transaction check failed (tx hash %s) %s", tx->GetHash().ToString(), state.GetDebugMessage()));

    unsigned int nSigOps = 0;
    for (const auto& tx : block.vtx)
    {
        nSigOps += GetLegacySigOpCount(*tx);
    }
    if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-sigops", false, "out-of-bounds SigOpCount");

    if (fCheckBMM && fCheckMerkleRoot)
        block.fChecked = true;

    return true;
}

bool VerifyBMM(const CBlock& block)
{
    // Skip genesis block
    if (block.GetHash() == Params().GetConsensus().hashGenesisBlock)
        return true;

    // Have we already verified BMM for this block?
    if (bmmCache.HaveVerifiedBMM(block.GetHash()))
        return true;

    // h*
    const uint256 hashMerkleRoot = block.hashMerkleRoot;

    // TODO
    // Return results from client to help decide on DoS score

    // Verify BMM with local mainchain node
    uint256 txid;
    uint32_t nTime;
    SidechainClient client;
    if (!client.VerifyBMM(block.hashMainchainBlock, hashMerkleRoot, txid, nTime)) {
        LogPrintf("%s: Did not find BMM h*: %s in mainchain block: %s!\n", __func__, hashMerkleRoot.ToString(), block.hashMainchainBlock.ToString());
        return false;
    }

    // Cache that we have verified BMM for this block
    bmmCache.CacheVerifiedBMM(block.GetHash());

    return true;
}

bool VerifyDeposit(const uint256& hashMainBlock, const uint256& txid, const int nTx)
{
    if (hashMainBlock.IsNull()) {
        return false;
    }
    if (txid.IsNull()) {
        return false;
    }

    // Have we already verified the deposit?
    if (bmmCache.HaveVerifiedDeposit(txid))
        return true;

    SidechainClient client;
    if (!client.VerifyDeposit(hashMainBlock, txid, nTx)) {
        return false;
    }

    // Cache that we have verified the deposit
    bmmCache.CacheVerifiedDeposit(txid);

    return true;
}

bool IsWitnessEnabled(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    return (VersionBitsState(pindexPrev, params, Consensus::DEPLOYMENT_SEGWIT, versionbitscache) == THRESHOLD_ACTIVE);
}

// Compute at which vout of the block's coinbase transaction the witness
// commitment occurs, or -1 if not found.
static int GetWitnessCommitmentIndex(const CBlock& block)
{
    int commitpos = -1;
    if (!block.vtx.empty()) {
        for (size_t o = 0; o < block.vtx[0]->vout.size(); o++) {
            if (block.vtx[0]->vout[o].scriptPubKey.size() >= 38 && block.vtx[0]->vout[o].scriptPubKey[0] == OP_RETURN && block.vtx[0]->vout[o].scriptPubKey[1] == 0x24 && block.vtx[0]->vout[o].scriptPubKey[2] == 0xaa && block.vtx[0]->vout[o].scriptPubKey[3] == 0x21 && block.vtx[0]->vout[o].scriptPubKey[4] == 0xa9 && block.vtx[0]->vout[o].scriptPubKey[5] == 0xed) {
                commitpos = o;
            }
        }
    }
    return commitpos;
}

void UpdateUncommittedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    int commitpos = GetWitnessCommitmentIndex(block);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != -1 && IsWitnessEnabled(pindexPrev, consensusParams) && !block.vtx[0]->HasWitness()) {
        CMutableTransaction tx(*block.vtx[0]);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
}

std::vector<unsigned char> GenerateCoinbaseCommitment(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    std::vector<unsigned char> commitment;
    int commitpos = GetWitnessCommitmentIndex(block);
    std::vector<unsigned char> ret(32, 0x00);
    if (consensusParams.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout != 0) {
        if (commitpos == -1) {
            uint256 witnessroot = BlockWitnessMerkleRoot(block, nullptr);
            CHash256().Write(witnessroot.begin(), 32).Write(ret.data(), 32).Finalize(witnessroot.begin());
            CTxOut out;
            out.nValue = 0;
            out.scriptPubKey.resize(38);
            out.scriptPubKey[0] = OP_RETURN;
            out.scriptPubKey[1] = 0x24;
            out.scriptPubKey[2] = 0xaa;
            out.scriptPubKey[3] = 0x21;
            out.scriptPubKey[4] = 0xa9;
            out.scriptPubKey[5] = 0xed;
            memcpy(&out.scriptPubKey[6], witnessroot.begin(), 32);
            commitment = std::vector<unsigned char>(out.scriptPubKey.begin(), out.scriptPubKey.end());
            CMutableTransaction tx(*block.vtx[0]);
            tx.vout.push_back(out);
            block.vtx[0] = MakeTransactionRef(std::move(tx));
        }
    }
    UpdateUncommittedBlockStructures(block, pindexPrev, consensusParams);
    return commitment;
}

CScript GenerateWithdrawalBundleFailCommit(const uint256& hashWithdrawalBundle)
{
    /*
     * Generate a script commit indicating that the Withdrawal Bundle failed on the mainchain
     */

    CScript scriptPubKey;

    // Add script header
    scriptPubKey.resize(37);
    scriptPubKey[0] = OP_RETURN;
    scriptPubKey[1] = 0xFA;
    scriptPubKey[2] = 0x86;
    scriptPubKey[3] = 0xC6;
    scriptPubKey[4] = 0x89;

    // Add Withdrawal Bundle hash
    memcpy(&scriptPubKey[5], hashWithdrawalBundle.begin(), 32);

    return scriptPubKey;
}

CScript GenerateWithdrawalBundleSpentCommit(const uint256& hashWithdrawalBundle)
{
    /*
     * Generate a script commit indicating that the Withdrawal Bundle was spent by mainchain
     */

    CScript scriptPubKey;

    // Add script header
    scriptPubKey.resize(37);
    scriptPubKey[0] = OP_RETURN;
    scriptPubKey[1] = 0xFB;
    scriptPubKey[2] = 0x53;
    scriptPubKey[3] = 0x45;
    scriptPubKey[4] = 0xDE;

    // Add Withdrawal Bundle hash
    memcpy(&scriptPubKey[5], hashWithdrawalBundle.begin(), 32);

    return scriptPubKey;
}

CScript GenerateWithdrawalRefundRequest(const uint256& id, const std::vector<unsigned char>& vchSig)
{
    /*
     * Generate a script commit indicating that the Withdrawal Bundle failed on the mainchain
     */

    CScript scriptPubKey;

    // Add script header
    scriptPubKey.resize(102);
    scriptPubKey[0] = OP_RETURN;
    scriptPubKey[1] = 0xFC;
    scriptPubKey[2] = 0xD2;
    scriptPubKey[3] = 0xE5;
    scriptPubKey[4] = 0x46;

    // Add Withdrawal ID (the ID it has in ldb)
    memcpy(&scriptPubKey[5], id.begin(), 32);

    // Add vchSig
    memcpy(&scriptPubKey[37], vchSig.data(), 65);

    return scriptPubKey;
}

CScript GeneratePrevBlockCommit(const uint256& hashPrevMain, const uint256& hashPrevSide)
{
    /*
     * Generate a script commit of previous mainchain & sidechain block hashes
     */

    CScript scriptPubKey;

    // Add script header
    scriptPubKey.resize(69);
    scriptPubKey[0] = OP_RETURN;
    scriptPubKey[1] = 0xFD;
    scriptPubKey[2] = 0x7A;
    scriptPubKey[3] = 0xD1;
    scriptPubKey[4] = 0xEF;

    // Add previous mainchain & previous sidechain block hash
    memcpy(&scriptPubKey[5], hashPrevMain.begin(), 32);
    memcpy(&scriptPubKey[37], hashPrevSide.begin(), 32);

    return scriptPubKey;
}

CScript GenerateWithdrawalBundleHashCommit(const uint256& hashWithdrawalBundle)
{
    /*
     * Generate a script commit of current Withdrawal Bundle hash
     */

    CScript scriptPubKey;

    // Add script header
    scriptPubKey.resize(37);
    scriptPubKey[0] = OP_RETURN;
    scriptPubKey[1] = 0xEF;
    scriptPubKey[2] = 0x5D;
    scriptPubKey[3] = 0x1D;
    scriptPubKey[4] = 0xFE;

    // Add Withdrawal Bundle hash
    memcpy(&scriptPubKey[5], hashWithdrawalBundle.begin(), 32);

    return scriptPubKey;
}

CScript GenerateBlockVersionCommit(const int32_t nVersion)
{
    /*
     * Generate a script commit of block version
     */

    CScript scriptPubKey;

    // Add script header
    scriptPubKey.resize(9);
    scriptPubKey[0] = OP_RETURN;
    scriptPubKey[1] = 0xA7;
    scriptPubKey[2] = 0xE6;
    scriptPubKey[3] = 0x7E;
    scriptPubKey[4] = 0x1F;

    CScriptNum num(nVersion);
    std::vector<unsigned char> vch = num.getvch();

    // Add version
    memcpy(&scriptPubKey[5], vch.data(), 4);

    return scriptPubKey;
}

bool VerifyWithdrawalRefundRequest(const uint256& id, const std::vector<unsigned char>& vchSig, SidechainWithdrawal& withdrawal)
{
    if (id.IsNull()) {
        LogPrintf("%s: Null Withdrawal ID!\n", __func__);
        return false;
    }
    if (vchSig.size() != 65) {
        LogPrintf("%s: Invalid signature size!\n", __func__);
        return false;
    }

    // Regenerate standard refund message & get hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strRefundMessageMagic;
    ss << id.ToString();

    // Recover the public key that signed the refund request
    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig)) {
        LogPrintf("%s: Failed to recover pubkey!\n", __func__);
        return false;
    }

    // Lookup & verify status of Withdrawal
    if (!psidechaintree->GetWithdrawal(id, withdrawal)) {
        LogPrintf("%s: Withdrawal not found!\n", __func__);
        return false;
    }
    // Check status of Withdrawal
    if (withdrawal.status != WITHDRAWAL_UNSPENT) {
        LogPrintf("%s: Withdrawal status != Withdrawal_UNSPENT\n", __func__);
        return false;
    }
    // Verify refund address matches the one recreated from signature
    if (DecodeDestination(withdrawal.strRefundDestination) != CTxDestination(pubkey.GetID())) {
        LogPrintf("%s: Refund address does not match signature!\n", __func__);
        return false;
    }

    return true;
}

/** Context-dependent validity checks.
 *  By "context", we mean only the previous block headers, but not the UTXO
 *  set; UTXO-related validity checks are done in ConnectBlock().
 *  NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 */
static bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, const CChainParams& params, const CBlockIndex* pindexPrev, int64_t nAdjustedTime)
{
    assert(pindexPrev != nullptr);
    const int nHeight = pindexPrev->nHeight + 1;
    const Consensus::Params& consensusParams = params.GetConsensus();

    // Check against checkpoints
    if (fCheckpointsEnabled) {
        // Don't accept any forks from the main chain prior to last checkpoint.
        // GetLastCheckpoint finds the last checkpoint in MapCheckpoints that's in our
        // MapBlockIndex.
        CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(params.Checkpoints());
        if (pcheckpoint && nHeight < pcheckpoint->nHeight)
            return state.DoS(100, error("%s: forked chain older than last checkpoint (height %d)", __func__, nHeight), REJECT_CHECKPOINT, "bad-fork-prior-to-checkpoint");
    }

    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(false, REJECT_INVALID, "time-too-old", "block's timestamp is too early");

    // Check timestamp
    if (block.GetBlockTime() > nAdjustedTime + MAX_FUTURE_BLOCK_TIME)
        return state.Invalid(false, REJECT_INVALID, "time-too-new", "block timestamp too far in the future");

    // Reject outdated version blocks when 95% (75% on testnet) of the network has upgraded:
    // check for version 2, 3 and 4 upgrades
    if((block.nVersion < 2 && nHeight >= consensusParams.BIP34Height) ||
       (block.nVersion < 3 && nHeight >= consensusParams.BIP66Height) ||
       (block.nVersion < 4 && nHeight >= consensusParams.BIP65Height))
            return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-version(0x%08x)", block.nVersion),
                                 strprintf("rejected nVersion=0x%08x block", block.nVersion));

    return true;
}

/** NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 */
static bool ContextualCheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    const int nHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;

    // Start enforcing BIP113 (Median Time Past) using versionbits logic.
    int nLockTimeFlags = 0;
    if (VersionBitsState(pindexPrev, consensusParams, Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) {
        nLockTimeFlags |= LOCKTIME_MEDIAN_TIME_PAST;
    }

    int64_t nLockTimeCutoff = (nHeight && nLockTimeFlags & LOCKTIME_MEDIAN_TIME_PAST)
                              ? pindexPrev->GetMedianTimePast()
                              : block.GetBlockTime();

    // Check that all transactions are finalized
    for (const auto& tx : block.vtx) {
        if (!IsFinalTx(*tx, nHeight, nLockTimeCutoff)) {
            return state.DoS(10, false, REJECT_INVALID, "bad-txns-nonfinal", false, "non-final transaction");
        }
    }

    // Enforce rule that the coinbase starts with serialized block height
    if (nHeight >= consensusParams.BIP34Height)
    {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) {
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-height", false, "block height mismatch in coinbase");
        }
    }

    // Validation for witness commitments.
    // * We compute the witness hash (which is the hash including witnesses) of all the block's transactions, except the
    //   coinbase (where 0x0000....0000 is used instead).
    // * The coinbase scriptWitness is a stack of a single 32-byte vector, containing a witness nonce (unconstrained).
    // * We build a merkle tree with all those witness hashes as leaves (similar to the hashMerkleRoot in the block header).
    // * There must be at least one output whose scriptPubKey is a single 36-byte push, the first 4 bytes of which are
    //   {0xaa, 0x21, 0xa9, 0xed}, and the following 32 bytes are SHA256^2(witness root, witness nonce). In case there are
    //   multiple, the last one is used.
    bool fHaveWitness = false;
    if (VersionBitsState(pindexPrev, consensusParams, Consensus::DEPLOYMENT_SEGWIT, versionbitscache) == THRESHOLD_ACTIVE) {
        int commitpos = GetWitnessCommitmentIndex(block);
        if (commitpos != -1) {
            bool malleated = false;
            uint256 hashWitness = BlockWitnessMerkleRoot(block, &malleated);
            // The malleation check is ignored; as the transaction tree itself
            // already does not permit it, it is impossible to trigger in the
            // witness tree.
            if (block.vtx[0]->vin[0].scriptWitness.stack.size() != 1 || block.vtx[0]->vin[0].scriptWitness.stack[0].size() != 32) {
                return state.DoS(100, false, REJECT_INVALID, "bad-witness-nonce-size", true, strprintf("%s : invalid witness nonce size", __func__));
            }
            CHash256().Write(hashWitness.begin(), 32).Write(&block.vtx[0]->vin[0].scriptWitness.stack[0][0], 32).Finalize(hashWitness.begin());
            if (memcmp(hashWitness.begin(), &block.vtx[0]->vout[commitpos].scriptPubKey[6], 32)) {
                return state.DoS(100, false, REJECT_INVALID, "bad-witness-merkle-match", true, strprintf("%s : witness merkle commitment mismatch", __func__));
            }
            fHaveWitness = true;
        }
    }

    // No witness data is allowed in blocks that don't commit to witness data, as this would otherwise leave room for spam
    if (!fHaveWitness) {
      for (const auto& tx : block.vtx) {
            if (tx->HasWitness()) {
                return state.DoS(100, false, REJECT_INVALID, "unexpected-witness", true, strprintf("%s : unexpected witness data found", __func__));
            }
        }
    }

    // After the coinbase witness nonce and commitment are verified,
    // we can check if the block weight passes (before we've checked the
    // coinbase witness, it would be possible for the weight to be too
    // large by filling up the coinbase witness, which doesn't change
    // the block hash, so we couldn't mark the block as permanently
    // failed).
    if (GetBlockWeight(block) > MAX_BLOCK_WEIGHT) {
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-weight", false, strprintf("%s : weight limit failed", __func__));
    }

    return true;
}

bool CChainState::AcceptBlockHeader(const CBlockHeader& block, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex)
{
    AssertLockHeld(cs_main);

    uint256 hash = block.GetHash();

    bool fGenesis = (hash == Params().GetConsensus().hashGenesisBlock);

    // Check for mainchain connection
    if (!fGenesis && !CheckMainchainConnection()) {
        SetNetworkActive(false, "Failed to connect to mainchain when checking block header!");
        return false;
    }

    // Check for duplicate
    BlockMap::iterator miSelf = mapBlockIndex.find(hash);
    CBlockIndex *pindex = nullptr;
    if (!fGenesis) {
        if (miSelf != mapBlockIndex.end()) {
            // Block header is already known.
            pindex = miSelf->second;
            if (ppindex)
                *ppindex = pindex;
            if (pindex->nStatus & BLOCK_FAILED_MASK)
                return state.Invalid(error("%s: block %s is marked invalid", __func__, hash.ToString()), 0, "duplicate");
            return true;
        }

        if (!VerifyBMM(block))
            return state.DoS(1, false, REJECT_INVALID, "bad-bmm", true, "Invalid BMM in block header!");

        // Get prev block index
        CBlockIndex* pindexPrev = nullptr;
        BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        if (mi == mapBlockIndex.end())
            return state.DoS(10, error("%s: prev block not found", __func__), 0, "prev-blk-not-found");
        pindexPrev = (*mi).second;
        if (pindexPrev->nStatus & BLOCK_FAILED_MASK)
            return state.DoS(100, error("%s: prev block invalid", __func__), REJECT_INVALID, "bad-prevblk");
        if (!ContextualCheckBlockHeader(block, state, chainparams, pindexPrev, GetAdjustedTime()))
            return error("%s: Consensus::ContextualCheckBlockHeader: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));

        if (!pindexPrev->IsValid(BLOCK_VALID_SCRIPTS)) {
            for (const CBlockIndex* failedit : g_failed_blocks) {
                if (pindexPrev->GetAncestor(failedit->nHeight) == failedit) {
                    assert(failedit->nStatus & BLOCK_FAILED_VALID);
                    CBlockIndex* invalid_walk = pindexPrev;
                    while (invalid_walk != failedit) {
                        invalid_walk->nStatus |= BLOCK_FAILED_CHILD;
                        setDirtyBlockIndex.insert(invalid_walk);
                        invalid_walk = invalid_walk->pprev;
                    }
                    return state.DoS(100, error("%s: prev block invalid", __func__), REJECT_INVALID, "bad-prevblk");
                }
            }
        }
    }
    if (pindex == nullptr)
        pindex = AddToBlockIndex(block);

    if (ppindex)
        *ppindex = pindex;

    CheckBlockIndex(chainparams.GetConsensus());

    return true;
}

// Exposed wrapper for AcceptBlockHeader
bool ProcessNewBlockHeaders(const std::vector<CBlockHeader>& headers, CValidationState& state, const CChainParams& chainparams, const CBlockIndex** ppindex, CBlockHeader *first_invalid)
{
    bool fReorg = false;
    std::vector<uint256> vOrphan;
    if (!UpdateMainBlockHashCache(fReorg, vOrphan)) {
        LogPrintf("%s: Failed to update main block hash cache!\n", __func__);
        return false;
    }
    if (fReorg)
        HandleMainchainReorg(vOrphan);

    if (first_invalid != nullptr) first_invalid->SetNull();
    {
        LOCK(cs_main);
        for (const CBlockHeader& header : headers) {
            CBlockIndex *pindex = nullptr; // Use a temp pindex instead of ppindex to avoid a const_cast
            if (!g_chainstate.AcceptBlockHeader(header, state, chainparams, &pindex)) {
                if (first_invalid) *first_invalid = header;
                return false;
            }
            if (ppindex) {
                *ppindex = pindex;
            }
        }
    }
    NotifyHeaderTip();
    return true;
}

/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
static CDiskBlockPos SaveBlockToDisk(const CBlock& block, int nHeight, const CChainParams& chainparams, const CDiskBlockPos* dbp) {
    unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
    CDiskBlockPos blockPos;
    if (dbp != nullptr)
        blockPos = *dbp;
    if (!FindBlockPos(blockPos, nBlockSize+8, nHeight, block.GetBlockTime(), dbp != nullptr)) {
        error("%s: FindBlockPos failed", __func__);
        return CDiskBlockPos();
    }
    if (dbp == nullptr) {
        if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart())) {
            AbortNode("Failed to write block");
            return CDiskBlockPos();
        }
    }
    return blockPos;
}

/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
bool CChainState::AcceptBlock(const std::shared_ptr<const CBlock>& pblock, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex, bool fRequested, const CDiskBlockPos* dbp, bool* fNewBlock)
{
    const CBlock& block = *pblock;

    if (fNewBlock) *fNewBlock = false;
    AssertLockHeld(cs_main);

    CBlockIndex *pindexDummy = nullptr;
    CBlockIndex *&pindex = ppindex ? *ppindex : pindexDummy;

    if (!AcceptBlockHeader(block, state, chainparams, &pindex))
        return false;

    // Try to process all requested blocks that we don't have, but only
    // process an unrequested block if it's new and has enough work to
    // advance our tip, and isn't too many blocks ahead.
    bool fAlreadyHave = pindex->nStatus & BLOCK_HAVE_DATA;
    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead = (pindex->nHeight > int(chainActive.Height() + MIN_BLOCKS_TO_KEEP));

    // TODO: Decouple this function from the block download logic by removing fRequested
    // This requires some new chain data structure to efficiently look up if a
    // block is in a chain leading to a candidate for best tip, despite not
    // being such a candidate itself.

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave) return true;
    if (!fRequested) {  // If we didn't ask for it:
        if (pindex->nTx != 0) return true;    // This is a previously-processed block that was pruned
        if (fTooFarAhead) return true;        // Block height is too high
    }
    if (fNewBlock) *fNewBlock = true;

    // Note that checkblock verifies BMM
    if (!CheckBlock(block, state, chainparams.GetConsensus()) ||
        !ContextualCheckBlock(block, state, chainparams.GetConsensus(), pindex->pprev)) {
        if (state.IsInvalid() && !state.CorruptionPossible()) {
            pindex->nStatus |= BLOCK_FAILED_VALID;
            setDirtyBlockIndex.insert(pindex);
        }
        return error("%s: %s", __func__, FormatStateMessage(state));
    }

    bool fInitialBlockDownload = IsInitialBlockDownload();

    bool fNewTip = (chainActive.Tip() == pindex->pprev);
    bool fVerifyWithdrawalBundleAcceptBlock = gArgs.GetBoolArg("-verifywithdrawalbundleacceptblock", DEFAULT_VERIFY_WITHDRAWAL_BUNDLE_ACCEPT_BLOCK);
    if (fVerifyWithdrawalBundleAcceptBlock && fNewTip && !fInitialBlockDownload) {
        // Note that here we call VerifyWithdrawalBundles with fReplicate set so that we
        // replicate the Withdrawal Bundle on our own and verify that it matches the Withdrawal Bundle in
        // this new block if there are any.
        std::string strFail = "";
        std::vector<SidechainWithdrawal> vWithdrawal;
        uint256 hashWithdrawalBundle;
        uint256 hashWithdrawalBundleID;
        if (!VerifyWithdrawalBundles(strFail, pindex->nHeight, block.vtx, vWithdrawal, hashWithdrawalBundle, hashWithdrawalBundleID, true /* fReplicate */)) {
            state.Error(strprintf("%s: invalid-withdrawal-bundle error: %s", __func__, strFail));
            return error("%s: invalid Withdrawal Bundle! Error: %s", __func__, strFail);
        }
    }

    // Header is valid/has work, merkle tree and segwit merkle tree are good...RELAY NOW
    // (but if it does not build on our best tip, let the SendMessages loop relay it)
    if (!fInitialBlockDownload && chainActive.Tip() == pindex->pprev)
        GetMainSignals().NewPoWValidBlock(pindex, pblock);

    // Write block to history file
    try {
        CDiskBlockPos blockPos = SaveBlockToDisk(block, pindex->nHeight, chainparams, dbp);
        if (blockPos.IsNull()) {
            state.Error(strprintf("%s: Failed to find position to write new block to disk", __func__));
            return false;
        }
        if (!ReceivedBlockTransactions(block, state, pindex, blockPos, chainparams.GetConsensus()))
            return error("AcceptBlock(): ReceivedBlockTransactions failed");
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error: ") + e.what());
    }

    if (fCheckForPruning)
        FlushStateToDisk(chainparams, state, FLUSH_STATE_NONE); // we just allocated more disk space for block files

    CheckBlockIndex(chainparams.GetConsensus());

    return true;
}

bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, bool fForceProcessing, bool *fNewBlock, bool fUnitTest)
{
    bool fReorg = false;
    std::vector<uint256> vOrphan;
    if (!UpdateMainBlockHashCache(fReorg, vOrphan)) {
        LogPrintf("%s: Failed to update main block hash cache!\n", __func__);
        if (!fUnitTest)
            return false;
    }
    if (fReorg)
        HandleMainchainReorg(vOrphan);

    AssertLockNotHeld(cs_main);

    {
        CBlockIndex *pindex = nullptr;
        if (fNewBlock) *fNewBlock = false;
        CValidationState state;
        // Ensure that CheckBlock() passes before calling AcceptBlock, as
        // belt-and-suspenders.
        bool ret = CheckBlock(*pblock, state, chainparams.GetConsensus());

        LOCK(cs_main);

        if (ret) {
            // Store to disk
            ret = g_chainstate.AcceptBlock(pblock, state, chainparams, &pindex, fForceProcessing, nullptr, fNewBlock);
        }
        if (!ret) {
            GetMainSignals().BlockChecked(*pblock, state);
            return error("%s: AcceptBlock FAILED (%s)", __func__, state.GetDebugMessage());
        }
    }

    NotifyHeaderTip();

    CValidationState state; // Only used to report errors, not invalidity - ignore it
    if (!g_chainstate.ActivateBestChain(state, chainparams, pblock))
        return error("%s: ActivateBestChain failed", __func__);

    return true;
}

bool TestBlockValidity(CValidationState& state, const CChainParams& chainparams, const CBlock& block, CBlockIndex* pindexPrev, bool fCheckMerkleRoot, bool fCheckBMM, bool fReorg)
{
    AssertLockHeld(cs_main);
    assert(pindexPrev);
    if (!fReorg)
        assert(pindexPrev == chainActive.Tip());
    CCoinsViewCache viewNew(pcoinsTip.get());
    CBlockIndex indexDummy(block);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev->nHeight + 1;

    if (!ContextualCheckBlockHeader(block, state, chainparams, pindexPrev, GetAdjustedTime()))
        return error("%s: Consensus::ContextualCheckBlockHeader: %s", __func__, FormatStateMessage(state));
    if (!CheckBlock(block, state, chainparams.GetConsensus(), fCheckMerkleRoot, fCheckBMM))
        return error("%s: Consensus::CheckBlock: %s", __func__, FormatStateMessage(state));
    if (!ContextualCheckBlock(block, state, chainparams.GetConsensus(), pindexPrev))
        return error("%s: Consensus::ContextualCheckBlock: %s", __func__, FormatStateMessage(state));

    if (!fReorg) {
        if (!g_chainstate.ConnectBlock(block, state, &indexDummy, viewNew, chainparams, true, fCheckBMM))
            return false;
    }

    assert(state.IsValid());

    return true;
}

/**
 * BLOCK PRUNING CODE
 */

/* Calculate the amount of disk space the block & undo files currently use */
uint64_t CalculateCurrentUsage()
{
    LOCK(cs_LastBlockFile);

    uint64_t retval = 0;
    for (const CBlockFileInfo &file : vinfoBlockFile) {
        retval += file.nSize + file.nUndoSize;
    }
    return retval;
}

/* Prune a block file (modify associated database entries)*/
void PruneOneBlockFile(const int fileNumber)
{
    LOCK(cs_LastBlockFile);

    for (const auto& entry : mapBlockIndex) {
        CBlockIndex* pindex = entry.second;
        if (pindex->nFile == fileNumber) {
            pindex->nStatus &= ~BLOCK_HAVE_DATA;
            pindex->nStatus &= ~BLOCK_HAVE_UNDO;
            pindex->nFile = 0;
            pindex->nDataPos = 0;
            pindex->nUndoPos = 0;
            setDirtyBlockIndex.insert(pindex);

            // Prune from mapBlocksUnlinked -- any block we prune would have
            // to be downloaded again in order to consider its chain, at which
            // point it would be considered as a candidate for
            // mapBlocksUnlinked or setBlockIndexCandidates.
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pindex->pprev);
            while (range.first != range.second) {
                std::multimap<CBlockIndex *, CBlockIndex *>::iterator _it = range.first;
                range.first++;
                if (_it->second == pindex) {
                    mapBlocksUnlinked.erase(_it);
                }
            }
        }
    }

    vinfoBlockFile[fileNumber].SetNull();
    setDirtyFileInfo.insert(fileNumber);
}


void UnlinkPrunedFiles(const std::set<int>& setFilesToPrune)
{
    for (std::set<int>::iterator it = setFilesToPrune.begin(); it != setFilesToPrune.end(); ++it) {
        CDiskBlockPos pos(*it, 0);
        fs::remove(GetBlockPosFilename(pos, "blk"));
        fs::remove(GetBlockPosFilename(pos, "rev"));
        LogPrintf("Prune: %s deleted blk/rev (%05u)\n", __func__, *it);
    }
}

/* Calculate the block/rev files to delete based on height specified by user with RPC command pruneblockchain */
static void FindFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight)
{
    assert(fPruneMode && nManualPruneHeight > 0);

    LOCK2(cs_main, cs_LastBlockFile);
    if (chainActive.Tip() == nullptr)
        return;

    // last block to prune is the lesser of (user-specified height, MIN_BLOCKS_TO_KEEP from the tip)
    unsigned int nLastBlockWeCanPrune = std::min((unsigned)nManualPruneHeight, chainActive.Tip()->nHeight - MIN_BLOCKS_TO_KEEP);
    int count=0;
    for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
        if (vinfoBlockFile[fileNumber].nSize == 0 || vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
            continue;
        PruneOneBlockFile(fileNumber);
        setFilesToPrune.insert(fileNumber);
        count++;
    }
    LogPrintf("Prune (Manual): prune_height=%d removed %d blk/rev pairs\n", nLastBlockWeCanPrune, count);
}

/* This function is called from the RPC code for pruneblockchain */
void PruneBlockFilesManual(int nManualPruneHeight)
{
    CValidationState state;
    const CChainParams& chainparams = Params();
    FlushStateToDisk(chainparams, state, FLUSH_STATE_NONE, nManualPruneHeight);
}

/**
 * Prune block and undo files (blk???.dat and undo???.dat) so that the disk space used is less than a user-defined target.
 * The user sets the target (in MB) on the command line or in config file.  This will be run on startup and whenever new
 * space is allocated in a block or undo file, staying below the target. Changing back to unpruned requires a reindex
 * (which in this case means the blockchain must be re-downloaded.)
 *
 * Pruning functions are called from FlushStateToDisk when the global fCheckForPruning flag has been set.
 * Block and undo files are deleted in lock-step (when blk00003.dat is deleted, so is rev00003.dat.)
 * Pruning cannot take place until the longest chain is at least a certain length (100000 on mainnet, 1000 on testnet, 1000 on regtest).
 * Pruning will never delete a block within a defined distance (currently 288) from the active chain's tip.
 * The block index is updated by unsetting HAVE_DATA and HAVE_UNDO for any blocks that were stored in the deleted files.
 * A db flag records the fact that at least some block files have been pruned.
 *
 * @param[out]   setFilesToPrune   The set of file indices that can be unlinked will be returned
 */
static void FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight)
{
    LOCK2(cs_main, cs_LastBlockFile);
    if (chainActive.Tip() == nullptr || nPruneTarget == 0) {
        return;
    }
    if ((uint64_t)chainActive.Tip()->nHeight <= nPruneAfterHeight) {
        return;
    }

    unsigned int nLastBlockWeCanPrune = chainActive.Tip()->nHeight - MIN_BLOCKS_TO_KEEP;
    uint64_t nCurrentUsage = CalculateCurrentUsage();
    // We don't check to prune until after we've allocated new space for files
    // So we should leave a buffer under our target to account for another allocation
    // before the next pruning.
    uint64_t nBuffer = BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE;
    uint64_t nBytesToPrune;
    int count=0;

    if (nCurrentUsage + nBuffer >= nPruneTarget) {
        for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
            nBytesToPrune = vinfoBlockFile[fileNumber].nSize + vinfoBlockFile[fileNumber].nUndoSize;

            if (vinfoBlockFile[fileNumber].nSize == 0)
                continue;

            if (nCurrentUsage + nBuffer < nPruneTarget)  // are we below our target?
                break;

            // don't prune files that could have a block within MIN_BLOCKS_TO_KEEP of the main chain's tip but keep scanning
            if (vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
                continue;

            PruneOneBlockFile(fileNumber);
            // Queue up the files for removal
            setFilesToPrune.insert(fileNumber);
            nCurrentUsage -= nBytesToPrune;
            count++;
        }
    }

    LogPrint(BCLog::PRUNE, "Prune: target=%dMiB actual=%dMiB diff=%dMiB max_prune_height=%d removed %d blk/rev pairs\n",
           nPruneTarget/1024/1024, nCurrentUsage/1024/1024,
           ((int64_t)nPruneTarget - (int64_t)nCurrentUsage)/1024/1024,
           nLastBlockWeCanPrune, count);
}

bool CheckDiskSpace(uint64_t nAdditionalBytes)
{
    uint64_t nFreeBytesAvailable = fs::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
        return AbortNode("Disk space is low!", _("Error: Disk space is low!"));

    return true;
}

static FILE* OpenDiskFile(const CDiskBlockPos &pos, const char *prefix, bool fReadOnly)
{
    if (pos.IsNull())
        return nullptr;
    fs::path path = GetBlockPosFilename(pos, prefix);
    fs::create_directories(path.parent_path());
    FILE* file = fsbridge::fopen(path, fReadOnly ? "rb": "rb+");
    if (!file && !fReadOnly)
        file = fsbridge::fopen(path, "wb+");
    if (!file) {
        LogPrintf("Unable to open file %s\n", path.string());
        return nullptr;
    }
    if (pos.nPos) {
        if (fseek(file, pos.nPos, SEEK_SET)) {
            LogPrintf("Unable to seek to position %u of %s\n", pos.nPos, path.string());
            fclose(file);
            return nullptr;
        }
    }
    return file;
}

FILE* OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "blk", fReadOnly);
}

/** Open an undo file (rev?????.dat) */
static FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "rev", fReadOnly);
}

fs::path GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix)
{
    return GetDataDir() / "blocks" / strprintf("%s%05u.dat", prefix, pos.nFile);
}

CBlockIndex * CChainState::InsertBlockIndex(const uint256& hash, const uint256& hashMainBlock)
{
    if (hash.IsNull())
        return nullptr;

    // Return existing
    BlockMap::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    // Also track by mainchain commitment block hash
    if (!hashMainBlock.IsNull())
        mapBlockMainHashIndex[hashMainBlock] = pindexNew;

    return pindexNew;
}

bool CChainState::LoadBlockIndex(const Consensus::Params& consensus_params, CBlockTreeDB& blocktree)
{
    if (!blocktree.LoadBlockIndexGuts(consensus_params, [this](const uint256& hash, const uint256& hashMainBlock){ return this->InsertBlockIndex(hash, hashMainBlock); }))
        return false;

    boost::this_thread::interruption_point();

    // Calculate nChainWork
    std::vector<std::pair<int, CBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    for (const std::pair<uint256, CBlockIndex*>& item : mapBlockIndex)
    {
        CBlockIndex* pindex = item.second;
        vSortedByHeight.push_back(std::make_pair(pindex->nHeight, pindex));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());
    for (const std::pair<int, CBlockIndex*>& item : vSortedByHeight)
    {
        CBlockIndex* pindex = item.second;
        pindex->nTimeMax = (pindex->pprev ? std::max(pindex->pprev->nTimeMax, pindex->nTime) : pindex->nTime);
        // We can link the chain of blocks for which we've received transactions at some point.
        // Pruned nodes may have deleted the block.
        if (pindex->nTx > 0) {
            if (pindex->pprev) {
                if (pindex->pprev->nChainTx) {
                    pindex->nChainTx = pindex->pprev->nChainTx + pindex->nTx;
                } else {
                    pindex->nChainTx = 0;
                    mapBlocksUnlinked.insert(std::make_pair(pindex->pprev, pindex));
                }
            } else {
                pindex->nChainTx = pindex->nTx;
            }
        }
        if (!(pindex->nStatus & BLOCK_FAILED_MASK) && pindex->pprev && (pindex->pprev->nStatus & BLOCK_FAILED_MASK)) {
            pindex->nStatus |= BLOCK_FAILED_CHILD;
            setDirtyBlockIndex.insert(pindex);
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && (pindex->nChainTx || pindex->pprev == nullptr))
            setBlockIndexCandidates.insert(pindex);
        if (pindex->nStatus & BLOCK_FAILED_MASK && (!pindexBestInvalid))
            pindexBestInvalid = pindex;
        if (pindex->pprev)
            pindex->BuildSkip();
        if (pindex->IsValid(BLOCK_VALID_TREE) && (pindexBestHeader == nullptr || CBlockIndexWorkComparator()(pindexBestHeader, pindex)))
            pindexBestHeader = pindex;
    }

    return true;
}

bool static LoadBlockIndexDB(const CChainParams& chainparams)
{
    if (!g_chainstate.LoadBlockIndex(chainparams.GetConsensus(), *pblocktree))
        return false;

    // Load block file info
    pblocktree->ReadLastBlockFile(nLastBlockFile);
    vinfoBlockFile.resize(nLastBlockFile + 1);
    LogPrintf("%s: last block file = %i\n", __func__, nLastBlockFile);
    for (int nFile = 0; nFile <= nLastBlockFile; nFile++) {
        pblocktree->ReadBlockFileInfo(nFile, vinfoBlockFile[nFile]);
    }
    LogPrintf("%s: last block file info: %s\n", __func__, vinfoBlockFile[nLastBlockFile].ToString());
    for (int nFile = nLastBlockFile + 1; true; nFile++) {
        CBlockFileInfo info;
        if (pblocktree->ReadBlockFileInfo(nFile, info)) {
            vinfoBlockFile.push_back(info);
        } else {
            break;
        }
    }

    // Check presence of blk files
    LogPrintf("Checking all blk files are present...\n");
    std::set<int> setBlkDataFiles;
    for (const std::pair<uint256, CBlockIndex*>& item : mapBlockIndex)
    {
        CBlockIndex* pindex = item.second;
        if (pindex->nStatus & BLOCK_HAVE_DATA) {
            setBlkDataFiles.insert(pindex->nFile);
        }
    }
    for (std::set<int>::iterator it = setBlkDataFiles.begin(); it != setBlkDataFiles.end(); it++)
    {
        CDiskBlockPos pos(*it, 0);
        if (CAutoFile(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION).IsNull()) {
            return false;
        }
    }

    // Check whether we have ever pruned block & undo files
    pblocktree->ReadFlag("prunedblockfiles", fHavePruned);
    if (fHavePruned)
        LogPrintf("LoadBlockIndexDB(): Block files have previously been pruned\n");

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    pblocktree->ReadReindexing(fReindexing);
    if(fReindexing) fReindex = true;

    // Check whether we have a transaction index
    pblocktree->ReadFlag("txindex", fTxIndex);
    LogPrintf("%s: transaction index %s\n", __func__, fTxIndex ? "enabled" : "disabled");

    return true;
}

bool LoadChainTip(const CChainParams& chainparams)
{
    if (chainActive.Tip() && chainActive.Tip()->GetBlockHash() == pcoinsTip->GetBestBlock()) return true;

    if (pcoinsTip->GetBestBlock().IsNull() && mapBlockIndex.size() == 1) {
        // In case we just added the genesis block, connect it now, so
        // that we always have a chainActive.Tip() when we return.
        LogPrintf("%s: Connecting genesis block...\n", __func__);
        CValidationState state;
        if (!ActivateBestChain(state, chainparams)) {
            return false;
        }
    }

    // Load pointer to end of best chain
    BlockMap::iterator it = mapBlockIndex.find(pcoinsTip->GetBestBlock());
    if (it == mapBlockIndex.end())
        return false;
    chainActive.SetTip(it->second);

    g_chainstate.PruneBlockIndexCandidates();

    LogPrintf("Loaded best chain: hashBestChain=%s height=%d date=%s progress=%f\n",
        chainActive.Tip()->GetBlockHash().ToString(), chainActive.Height(),
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", chainActive.Tip()->GetBlockTime()),
        GuessVerificationProgress(chainparams.TxData(), chainActive.Tip()));
    return true;
}

CVerifyDB::CVerifyDB()
{
    uiInterface.ShowProgress(_("Verifying blocks..."), 0, false);
}

CVerifyDB::~CVerifyDB()
{
    uiInterface.ShowProgress("", 100, false);
}

bool CVerifyDB::VerifyDB(const CChainParams& chainparams, CCoinsView *coinsview, int nCheckLevel, int nCheckDepth)
{
    LOCK(cs_main);
    if (chainActive.Tip() == nullptr || chainActive.Tip()->pprev == nullptr)
        return true;

    // Verify blocks in the best chain
    if (nCheckDepth <= 0 || nCheckDepth > chainActive.Height())
        nCheckDepth = chainActive.Height();
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(coinsview);
    CBlockIndex* pindexState = chainActive.Tip();
    CBlockIndex* pindexFailure = nullptr;
    int nGoodTransactions = 0;
    CValidationState state;
    int reportDone = 0;
    LogPrintf("[0%%]...");
    for (CBlockIndex* pindex = chainActive.Tip(); pindex && pindex->pprev; pindex = pindex->pprev)
    {
        boost::this_thread::interruption_point();
        int percentageDone = std::max(1, std::min(99, (int)(((double)(chainActive.Height() - pindex->nHeight)) / (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100))));
        if (reportDone < percentageDone/10) {
            // report every 10% step
            LogPrintf("[%d%%]...", percentageDone);
            reportDone = percentageDone/10;
        }
        uiInterface.ShowProgress(_("Verifying blocks..."), percentageDone, false);
        if (pindex->nHeight < chainActive.Height()-nCheckDepth)
            break;
        if (fPruneMode && !(pindex->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning, only go back as far as we have data.
            LogPrintf("VerifyDB(): block verification stopping at height %d (pruning, no data)\n", pindex->nHeight);
            break;
        }
        CBlock block;
        // check level 0: read from disk
        if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
            return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state, chainparams.GetConsensus(),
                    true /* fCheckMerkleRoot */, false /* fCheckBMM */))
            return error("%s: *** found bad block at %d, hash=%s (%s)\n", __func__,
                         pindex->nHeight, pindex->GetBlockHash().ToString(), FormatStateMessage(state));
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            if (!pindex->GetUndoPos().IsNull()) {
                if (!UndoReadFromDisk(undo, pindex)) {
                    return error("VerifyDB(): *** found bad undo data at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                }
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        if (nCheckLevel >= 3 && pindex == pindexState && (coins.DynamicMemoryUsage() + pcoinsTip->DynamicMemoryUsage()) <= nCoinCacheUsage) {
            assert(coins.GetBestBlock() == pindex->GetBlockHash());
            // fSideDB=false: this is a throwaway-view verification pass - the
            // house/bill undo writes would hit the REAL side DBs and roll
            // them back on every restart without ever reconnecting (3.4
            // review CRITICAL).
            DisconnectResult res = g_chainstate.DisconnectBlock(block, pindex, coins, false /* fSideDB */);
            if (res == DISCONNECT_FAILED) {
                return error("VerifyDB(): *** irrecoverable inconsistency in block data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            }
            pindexState = pindex->pprev;
            if (res == DISCONNECT_UNCLEAN) {
                nGoodTransactions = 0;
                pindexFailure = pindex;
            } else {
                nGoodTransactions += block.vtx.size();
            }
        }
        if (ShutdownRequested())
            return true;
    }
    if (pindexFailure)
        return error("VerifyDB(): *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", chainActive.Height() - pindexFailure->nHeight + 1, nGoodTransactions);

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) {
        CBlockIndex *pindex = pindexState;
        while (pindex != chainActive.Tip()) {
            boost::this_thread::interruption_point();
            uiInterface.ShowProgress(_("Verifying blocks..."), std::max(1, std::min(99, 100 - (int)(((double)(chainActive.Height() - pindex->nHeight)) / (double)nCheckDepth * 50))), false);
            pindex = chainActive.Next(pindex);
            CBlock block;
            if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
                return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            if (!g_chainstate.ConnectBlock(block, state, pindex, coins,
                        chainparams, false /* fJustCheck */, false /* fCheckBMM */))
                return error("VerifyDB(): *** found unconnectable block at %d, hash=%s.\n Error: %s\n", pindex->nHeight, pindex->GetBlockHash().ToString(), FormatStateMessage(state));
        }
    }

    LogPrintf("[DONE].\n");
    LogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n", chainActive.Height() - pindexState->nHeight, nGoodTransactions);

    return true;
}

/** Apply the effects of a block on the utxo cache, ignoring that it may already have been applied. */
bool CChainState::RollforwardBlock(const CBlockIndex* pindex, CCoinsViewCache& inputs, const CChainParams& params)
{
    // TODO: merge with ConnectBlock
    CBlock block;
    if (!ReadBlockFromDisk(block, pindex, params.GetConsensus())) {
        return error("ReplayBlock(): ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
    }

    for (const CTransactionRef& tx : block.vtx) {
        if (tx->IsCoinBase())
            continue;

        // Per-tx (NOT accumulated across the block): a stale amountAssetIn from
        // an earlier asset tx would send a later bill/house tx's outputs down
        // AddCoins' asset-coloring branch and drop their fBill/fHouseEscrow tag
        // (pre-existing chassis bug; UpdateCoins resets these every call).
        CAmount amountAssetIn = CAmount(0);
        int nControlN = -1;
        uint32_t nAssetID = 0;

        for (size_t x = 0; x < tx->vin.size(); x++) {
            bool fBitAsset = false;
            bool fBitAssetControl = false;
            Coin coin;
            inputs.SpendCoin(tx->vin[x].prevout, fBitAsset, fBitAssetControl, nAssetID, &coin);

            if (fBitAsset)
                amountAssetIn += coin.out.nValue;
            if (fBitAssetControl)
                nControlN = x;
        }

        // Re-tag bill title / escrow outputs. BillDB is written synchronously
        // per block in ConnectBlock, so it is already current here (only the
        // coins DB lags); recover the dense id for ISSUE from the body hash and
        // for ENDORSE from the payload.
        uint32_t nBillID = 0;
        if (tx->nVersion == TRANSACTION_BILL_VERSION) {
            if (tx->nBillOp == BILL_OP_ISSUE) {
                BillIssue issue;
                if (DecodeBillPayload(tx->vchBillPayload, issue))
                    pbilltree->GetBillIDByHash(BillIDFromBody(issue.vchEncryptedBody), nBillID);
            } else if (tx->nBillOp == BILL_OP_ENDORSE) {
                BillEndorse endorse;
                if (DecodeBillPayload(tx->vchBillPayload, endorse))
                    nBillID = endorse.nBillID;
            }
        }

        // Re-tag house pledge outputs (HouseDB is already current here, like
        // BillDB above): REGISTER recovers its dense id via the declaration
        // hash; TOPUP / ADMIT carry it in the payload. RECLAIM only spends.
        uint32_t nHouseID = 0;
        if (tx->nVersion == TRANSACTION_HOUSE_VERSION) {
            if (tx->nHouseOp == HOUSE_OP_REGISTER) {
                HouseRegister reg;
                if (DecodeHousePayload(tx->vchHousePayload, reg))
                    phousetree->GetHouseIDByHash(HouseIDFromDeclaration(reg), nHouseID);
            } else if (tx->nHouseOp == HOUSE_OP_TOPUP) {
                HouseTopup topup;
                if (DecodeHousePayload(tx->vchHousePayload, topup))
                    nHouseID = topup.nHouseID;
            } else if (tx->nHouseOp == HOUSE_OP_ADMIT) {
                HouseAdmit admit;
                if (DecodeHousePayload(tx->vchHousePayload, admit))
                    nHouseID = admit.nHouseID;
            } else if (tx->nHouseOp == HOUSE_OP_DEFER) {
                HouseDefer def;
                if (DecodeHousePayload(tx->vchHousePayload, def))
                    nHouseID = def.nHouseID;
            }
        }

        // Pass check = true as every addition may be an overwrite.
        AddCoins(inputs, *tx, pindex->nHeight, nAssetID, amountAssetIn, nControlN, 0, nBillID, nHouseID, true);
    }
    return true;
}

bool CChainState::ReplayBlocks(const CChainParams& params, CCoinsView* view)
{
    LOCK(cs_main);

    CCoinsViewCache cache(view);

    std::vector<uint256> hashHeads = view->GetHeadBlocks();
    if (hashHeads.empty()) return true; // We're already in a consistent state.
    if (hashHeads.size() != 2) return error("ReplayBlocks(): unknown inconsistent state");

    uiInterface.ShowProgress(_("Replaying blocks..."), 0, false);
    LogPrintf("Replaying blocks\n");

    const CBlockIndex* pindexOld = nullptr;  // Old tip during the interrupted flush.
    const CBlockIndex* pindexNew;            // New tip during the interrupted flush.
    const CBlockIndex* pindexFork = nullptr; // Latest block common to both the old and the new tip.

    if (mapBlockIndex.count(hashHeads[0]) == 0) {
        return error("ReplayBlocks(): reorganization to unknown block requested");
    }
    pindexNew = mapBlockIndex[hashHeads[0]];

    if (!hashHeads[1].IsNull()) { // The old tip is allowed to be 0, indicating it's the first flush.
        if (mapBlockIndex.count(hashHeads[1]) == 0) {
            return error("ReplayBlocks(): reorganization from unknown block requested");
        }
        pindexOld = mapBlockIndex[hashHeads[1]];
        pindexFork = LastCommonAncestor(pindexOld, pindexNew);
        assert(pindexFork != nullptr);
    }

    // Rollback along the old branch.
    while (pindexOld != pindexFork) {
        if (pindexOld->nHeight > 0) { // Never disconnect the genesis block.
            CBlock block;
            if (!ReadBlockFromDisk(block, pindexOld, params.GetConsensus())) {
                return error("RollbackBlock(): ReadBlockFromDisk() failed at %d, hash=%s", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
            }
            LogPrintf("Rolling back %s (%i)\n", pindexOld->GetBlockHash().ToString(), pindexOld->nHeight);
            DisconnectResult res = DisconnectBlock(block, pindexOld, cache);
            if (res == DISCONNECT_FAILED) {
                return error("RollbackBlock(): DisconnectBlock failed at %d, hash=%s", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
            }
            // If DISCONNECT_UNCLEAN is returned, it means a non-existing UTXO was deleted, or an existing UTXO was
            // overwritten. It corresponds to cases where the block-to-be-disconnect never had all its operations
            // applied to the UTXO set. However, as both writing a UTXO and deleting a UTXO are idempotent operations,
            // the result is still a version of the UTXO set with the effects of that block undone.
        }
        pindexOld = pindexOld->pprev;
    }

    // Roll forward from the forking point to the new tip.
    int nForkHeight = pindexFork ? pindexFork->nHeight : 0;
    for (int nHeight = nForkHeight + 1; nHeight <= pindexNew->nHeight; ++nHeight) {
        const CBlockIndex* pindex = pindexNew->GetAncestor(nHeight);
        LogPrintf("Rolling forward %s (%i)\n", pindex->GetBlockHash().ToString(), nHeight);
        if (!RollforwardBlock(pindex, cache, params)) return false;
    }

    cache.SetBestBlock(pindexNew->GetBlockHash());
    cache.Flush();
    uiInterface.ShowProgress("", 100, false);
    return true;
}

bool ReplayBlocks(const CChainParams& params, CCoinsView* view) {
    return g_chainstate.ReplayBlocks(params, view);
}

bool CChainState::RewindBlockIndex(const CChainParams& params)
{
    LOCK(cs_main);

    // Note that during -reindex-chainstate we are called with an empty chainActive!

    int nHeight = 1;
    while (nHeight <= chainActive.Height()) {
        if (IsWitnessEnabled(chainActive[nHeight - 1], params.GetConsensus()) && !(chainActive[nHeight]->nStatus & BLOCK_OPT_WITNESS)) {
            break;
        }
        nHeight++;
    }

    // nHeight is now the height of the first insufficiently-validated block, or tipheight + 1
    CValidationState state;
    CBlockIndex* pindex = chainActive.Tip();
    while (chainActive.Height() >= nHeight) {
        if (fPruneMode && !(chainActive.Tip()->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning, don't try rewinding past the HAVE_DATA point;
            // since older blocks can't be served anyway, there's
            // no need to walk further, and trying to DisconnectTip()
            // will fail (and require a needless reindex/redownload
            // of the blockchain).
            break;
        }
        if (!DisconnectTip(state, params, nullptr)) {
            return error("RewindBlockIndex: unable to disconnect block at height %i", pindex->nHeight);
        }
        // Occasionally flush state to disk.
        if (!FlushStateToDisk(params, state, FLUSH_STATE_PERIODIC))
            return false;
    }

    // Reduce validity flag and have-data flags.
    // We do this after actual disconnecting, otherwise we'll end up writing the lack of data
    // to disk before writing the chainstate, resulting in a failure to continue if interrupted.
    for (const auto& entry : mapBlockIndex) {
        CBlockIndex* pindexIter = entry.second;

        // Note: If we encounter an insufficiently validated block that
        // is on chainActive, it must be because we are a pruning node, and
        // this block or some successor doesn't HAVE_DATA, so we were unable to
        // rewind all the way.  Blocks remaining on chainActive at this point
        // must not have their validity reduced.
        if (IsWitnessEnabled(pindexIter->pprev, params.GetConsensus()) && !(pindexIter->nStatus & BLOCK_OPT_WITNESS) && !chainActive.Contains(pindexIter)) {
            // Reduce validity
            pindexIter->nStatus = std::min<unsigned int>(pindexIter->nStatus & BLOCK_VALID_MASK, BLOCK_VALID_TREE) | (pindexIter->nStatus & ~BLOCK_VALID_MASK);
            // Remove have-data flags.
            pindexIter->nStatus &= ~(BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
            // Remove storage location.
            pindexIter->nFile = 0;
            pindexIter->nDataPos = 0;
            pindexIter->nUndoPos = 0;
            // Remove various other things
            pindexIter->nTx = 0;
            pindexIter->nChainTx = 0;
            pindexIter->nSequenceId = 0;
            // Make sure it gets written.
            setDirtyBlockIndex.insert(pindexIter);
            // Update indexes
            setBlockIndexCandidates.erase(pindexIter);
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> ret = mapBlocksUnlinked.equal_range(pindexIter->pprev);
            while (ret.first != ret.second) {
                if (ret.first->second == pindexIter) {
                    mapBlocksUnlinked.erase(ret.first++);
                } else {
                    ++ret.first;
                }
            }
        } else if (pindexIter->IsValid(BLOCK_VALID_TRANSACTIONS) && pindexIter->nChainTx) {
            setBlockIndexCandidates.insert(pindexIter);
        }
    }

    if (chainActive.Tip() != nullptr) {
        // We can't prune block index candidates based on our tip if we have
        // no tip due to chainActive being empty!
        PruneBlockIndexCandidates();

        CheckBlockIndex(params.GetConsensus());
    }

    return true;
}

bool RewindBlockIndex(const CChainParams& params) {
    if (!g_chainstate.RewindBlockIndex(params)) {
        return false;
    }

    if (chainActive.Tip() != nullptr) {
        // FlushStateToDisk can possibly read chainActive. Be conservative
        // and skip it here, we're about to -reindex-chainstate anyway, so
        // it'll get called a bunch real soon.
        CValidationState state;
        if (!FlushStateToDisk(params, state, FLUSH_STATE_ALWAYS)) {
            return false;
        }
    }

    return true;
}

void CChainState::UnloadBlockIndex() {
    nBlockSequenceId = 1;
    g_failed_blocks.clear();
    setBlockIndexCandidates.clear();
}

// May NOT be used after any connections are up as much
// of the peer-processing logic assumes a consistent
// block index state
void UnloadBlockIndex()
{
    LOCK(cs_main);
    chainActive.SetTip(nullptr);
    pindexBestInvalid = nullptr;
    pindexBestHeader = nullptr;
    mempool.clear();
    mapBlocksUnlinked.clear();
    vinfoBlockFile.clear();
    nLastBlockFile = 0;
    setDirtyBlockIndex.clear();
    setDirtyFileInfo.clear();
    versionbitscache.Clear();
    for (int b = 0; b < VERSIONBITS_NUM_BITS; b++) {
        warningcache[b].clear();
    }

    for (BlockMap::value_type& entry : mapBlockIndex) {
        delete entry.second;
    }
    mapBlockIndex.clear();
    mapBlockMainHashIndex.clear();
    fHavePruned = false;

    g_chainstate.UnloadBlockIndex();
}

bool LoadBlockIndex(const CChainParams& chainparams)
{
    // Load block index from databases
    bool needs_init = fReindex;
    if (!fReindex) {
        bool ret = LoadBlockIndexDB(chainparams);
        if (!ret) return false;
        needs_init = mapBlockIndex.empty();
    }

    if (needs_init) {
        // Everything here is for *new* reindex/DBs. Thus, though
        // LoadBlockIndexDB may have set fReindex if we shut down
        // mid-reindex previously, we don't check fReindex and
        // instead only check it prior to LoadBlockIndexDB to set
        // needs_init.

        LogPrintf("Initializing databases...\n");
        // Use the provided setting for -txindex in the new database
        fTxIndex = gArgs.GetBoolArg("-txindex", DEFAULT_TXINDEX);
        pblocktree->WriteFlag("txindex", fTxIndex);
        pblocktree->WriteFlag("sidechain", fSidechainIndex);
    }
    return true;
}

bool CChainState::LoadGenesisBlock(const CChainParams& chainparams)
{
    LOCK(cs_main);

    // Check whether we're already initialized by checking for genesis in
    // mapBlockIndex. Note that we can't use chainActive here, since it is
    // set based on the coins db, not the block index db, which is the only
    // thing loaded at this point.
    if (mapBlockIndex.count(chainparams.GenesisBlock().GetHash()))
        return true;

    try {
        CBlock &block = const_cast<CBlock&>(chainparams.GenesisBlock());
        CDiskBlockPos blockPos = SaveBlockToDisk(block, 0, chainparams, nullptr);
        if (blockPos.IsNull())
            return error("%s: writing genesis block to disk failed", __func__);
        CBlockIndex *pindex = AddToBlockIndex(block);
        CValidationState state;
        if (!ReceivedBlockTransactions(block, state, pindex, blockPos, chainparams.GetConsensus()))
            return error("%s: genesis block not accepted", __func__);
    } catch (const std::runtime_error& e) {
        return error("%s: failed to write genesis block: %s", __func__, e.what());
    }

    return true;
}

bool LoadGenesisBlock(const CChainParams& chainparams)
{
    return g_chainstate.LoadGenesisBlock(chainparams);
}

bool LoadExternalBlockFile(const CChainParams& chainparams, FILE* fileIn, CDiskBlockPos *dbp)
{
    // Map of disk positions for blocks with unknown parent (only used for reindex)
    static std::multimap<uint256, CDiskBlockPos> mapBlocksUnknownParent;
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    try {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2*MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SERIALIZED_SIZE+8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof()) {
            boost::this_thread::interruption_point();

            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[CMessageHeader::MESSAGE_START_SIZE];
                blkdat.FindByte(chainparams.MessageStart()[0]);
                nRewind = blkdat.GetPos()+1;
                blkdat >> FLATDATA(buf);
                if (memcmp(buf, chainparams.MessageStart(), CMessageHeader::MESSAGE_START_SIZE))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > MAX_BLOCK_SERIALIZED_SIZE)
                    continue;
            } catch (const std::exception&) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64_t nBlockPos = blkdat.GetPos();
                if (dbp)
                    dbp->nPos = nBlockPos;
                blkdat.SetLimit(nBlockPos + nSize);
                blkdat.SetPos(nBlockPos);
                std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
                CBlock& block = *pblock;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                // detect out of order blocks, and store them for later
                uint256 hash = block.GetHash();
                if (hash != chainparams.GetConsensus().hashGenesisBlock && mapBlockIndex.find(block.hashPrevBlock) == mapBlockIndex.end()) {
                    LogPrint(BCLog::REINDEX, "%s: Out of order block %s, parent %s not known\n", __func__, hash.ToString(),
                            block.hashPrevBlock.ToString());
                    if (dbp)
                        mapBlocksUnknownParent.insert(std::make_pair(block.hashPrevBlock, *dbp));
                    continue;
                }

                // process in case the block isn't known yet
                if (mapBlockIndex.count(hash) == 0 || (mapBlockIndex[hash]->nStatus & BLOCK_HAVE_DATA) == 0) {
                    LOCK(cs_main);
                    CValidationState state;
                    if (g_chainstate.AcceptBlock(pblock, state, chainparams, nullptr, true, dbp, nullptr))
                        nLoaded++;
                    if (state.IsError())
                        break;
                } else if (hash != chainparams.GetConsensus().hashGenesisBlock && mapBlockIndex[hash]->nHeight % 1000 == 0) {
                    LogPrint(BCLog::REINDEX, "Block Import: already had block %s at height %d\n", hash.ToString(), mapBlockIndex[hash]->nHeight);
                }

                // Activate the genesis block so normal node progress can continue
                if (hash == chainparams.GetConsensus().hashGenesisBlock) {
                    CValidationState state;
                    if (!ActivateBestChain(state, chainparams)) {
                        break;
                    }
                }

                NotifyHeaderTip();

                // Recursively process earlier encountered successors of this block
                std::deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty()) {
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, CDiskBlockPos>::iterator, std::multimap<uint256, CDiskBlockPos>::iterator> range = mapBlocksUnknownParent.equal_range(head);
                    while (range.first != range.second) {
                        std::multimap<uint256, CDiskBlockPos>::iterator it = range.first;
                        std::shared_ptr<CBlock> pblockrecursive = std::make_shared<CBlock>();
                        if (ReadBlockFromDisk(*pblockrecursive, it->second, chainparams.GetConsensus()))
                        {
                            LogPrint(BCLog::REINDEX, "%s: Processing out of order child %s of %s\n", __func__, pblockrecursive->GetHash().ToString(),
                                    head.ToString());
                            LOCK(cs_main);
                            CValidationState dummy;
                            if (g_chainstate.AcceptBlock(pblockrecursive, dummy, chainparams, nullptr, true, &it->second, nullptr))
                            {
                                nLoaded++;
                                queue.push_back(pblockrecursive->GetHash());
                            }
                        }
                        range.first++;
                        mapBlocksUnknownParent.erase(it);
                        NotifyHeaderTip();
                    }
                }
            } catch (const std::exception& e) {
                LogPrintf("%s: Deserialize or I/O error - %s\n", __func__, e.what());
            }
        }
    } catch (const std::runtime_error& e) {
        AbortNode(std::string("System error: ") + e.what());
    }
    if (nLoaded > 0)
        LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

void CChainState::CheckBlockIndex(const Consensus::Params& consensusParams)
{
    if (!fCheckBlockIndex) {
        return;
    }

    LOCK(cs_main);

    // During a reindex, we read the genesis block and call CheckBlockIndex before ActivateBestChain,
    // so we have the genesis block in mapBlockIndex but no active chain.  (A few of the tests when
    // iterating the block tree require that chainActive has been initialized.)
    if (chainActive.Height() < 0) {
        assert(mapBlockIndex.size() <= 1);
        return;
    }

    // Build forward-pointing map of the entire block tree.
    std::multimap<CBlockIndex*,CBlockIndex*> forward;
    for (auto& entry : mapBlockIndex) {
        forward.insert(std::make_pair(entry.second->pprev, entry.second));
    }

    assert(forward.size() == mapBlockIndex.size());

    std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeGenesis = forward.equal_range(nullptr);
    CBlockIndex *pindex = rangeGenesis.first->second;
    rangeGenesis.first++;
    assert(rangeGenesis.first == rangeGenesis.second); // There is only one index entry with parent nullptr.

    // Iterate over the entire block tree, using depth-first search.
    // Along the way, remember whether there are blocks on the path from genesis
    // block being explored which are the first to have certain properties.
    size_t nNodes = 0;
    int nHeight = 0;
    CBlockIndex* pindexFirstInvalid = nullptr; // Oldest ancestor of pindex which is invalid.
    CBlockIndex* pindexFirstMissing = nullptr; // Oldest ancestor of pindex which does not have BLOCK_HAVE_DATA.
    CBlockIndex* pindexFirstNeverProcessed = nullptr; // Oldest ancestor of pindex for which nTx == 0.
    CBlockIndex* pindexFirstNotTreeValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_TREE (regardless of being valid or not).
    CBlockIndex* pindexFirstNotTransactionsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_TRANSACTIONS (regardless of being valid or not).
    CBlockIndex* pindexFirstNotChainValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_CHAIN (regardless of being valid or not).
    CBlockIndex* pindexFirstNotScriptsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_SCRIPTS (regardless of being valid or not).
    while (pindex != nullptr) {
        nNodes++;
        if (pindexFirstInvalid == nullptr && pindex->nStatus & BLOCK_FAILED_VALID) pindexFirstInvalid = pindex;
        if (pindexFirstMissing == nullptr && !(pindex->nStatus & BLOCK_HAVE_DATA)) pindexFirstMissing = pindex;
        if (pindexFirstNeverProcessed == nullptr && pindex->nTx == 0) pindexFirstNeverProcessed = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotTreeValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE) pindexFirstNotTreeValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotTransactionsValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS) pindexFirstNotTransactionsValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotChainValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_CHAIN) pindexFirstNotChainValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotScriptsValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) pindexFirstNotScriptsValid = pindex;

        // Begin: actual consistency checks.
        if (pindex->pprev == nullptr) {
            // Genesis block checks.
            assert(pindex->GetBlockHash() == consensusParams.hashGenesisBlock); // Genesis block's hash must match.
            assert(pindex == chainActive.Genesis()); // The current active chain's genesis block must be this block.
        }
        if (pindex->nChainTx == 0) assert(pindex->nSequenceId <= 0);  // nSequenceId can't be set positive for blocks that aren't linked (negative is used for preciousblock)
        // VALID_TRANSACTIONS is equivalent to nTx > 0 for all nodes (whether or not pruning has occurred).
        // HAVE_DATA is only equivalent to nTx > 0 (or VALID_TRANSACTIONS) if no pruning has occurred.
        if (!fHavePruned) {
            // If we've never pruned, then HAVE_DATA should be equivalent to nTx > 0
            assert(!(pindex->nStatus & BLOCK_HAVE_DATA) == (pindex->nTx == 0));
            assert(pindexFirstMissing == pindexFirstNeverProcessed);
        } else {
            // If we have pruned, then we can only say that HAVE_DATA implies nTx > 0
            if (pindex->nStatus & BLOCK_HAVE_DATA) assert(pindex->nTx > 0);
        }
        if (pindex->nStatus & BLOCK_HAVE_UNDO) assert(pindex->nStatus & BLOCK_HAVE_DATA);
        assert(((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS) == (pindex->nTx > 0)); // This is pruning-independent.
        // All parents having had data (at some point) is equivalent to all parents being VALID_TRANSACTIONS, which is equivalent to nChainTx being set.
        assert((pindexFirstNeverProcessed != nullptr) == (pindex->nChainTx == 0)); // nChainTx != 0 is used to signal that all parent blocks have been processed (but may have been pruned).
        assert((pindexFirstNotTransactionsValid != nullptr) == (pindex->nChainTx == 0));
        assert(pindex->nHeight == nHeight); // nHeight must be consistent.
        assert(nHeight < 2 || (pindex->pskip && (pindex->pskip->nHeight < nHeight))); // The pskip pointer must point back for all but the first 2 blocks.
        assert(pindexFirstNotTreeValid == nullptr); // All mapBlockIndex entries must at least be TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE) assert(pindexFirstNotTreeValid == nullptr); // TREE valid implies all parents are TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_CHAIN) assert(pindexFirstNotChainValid == nullptr); // CHAIN valid implies all parents are CHAIN valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS) assert(pindexFirstNotScriptsValid == nullptr); // SCRIPTS valid implies all parents are SCRIPTS valid
        if (pindexFirstInvalid == nullptr) {
            // Checks for not-invalid blocks.
            assert((pindex->nStatus & BLOCK_FAILED_MASK) == 0); // The failed mask cannot be set for blocks without invalid parents.
        }
        if (!CBlockIndexWorkComparator()(pindex, chainActive.Tip()) && pindexFirstNeverProcessed == nullptr) {
            if (pindexFirstInvalid == nullptr) {
                // If this block sorts at least as good as the current tip and
                // is valid and we have all data for its parents, it must be in
                // setBlockIndexCandidates.  chainActive.Tip() must also be there
                // even if some data has been pruned.
                if (pindexFirstMissing == nullptr || pindex == chainActive.Tip()) {
                    assert(setBlockIndexCandidates.count(pindex));
                }
                // If some parent is missing, then it could be that this block was in
                // setBlockIndexCandidates but had to be removed because of the missing data.
                // In this case it must be in mapBlocksUnlinked -- see test below.
            }
        } else { // If this block sorts worse than the current tip or some ancestor's block has never been seen, it cannot be in setBlockIndexCandidates.
            assert(setBlockIndexCandidates.count(pindex) == 0);
        }
        // Check whether this block is in mapBlocksUnlinked.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeUnlinked = mapBlocksUnlinked.equal_range(pindex->pprev);
        bool foundInUnlinked = false;
        while (rangeUnlinked.first != rangeUnlinked.second) {
            assert(rangeUnlinked.first->first == pindex->pprev);
            if (rangeUnlinked.first->second == pindex) {
                foundInUnlinked = true;
                break;
            }
            rangeUnlinked.first++;
        }
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed != nullptr && pindexFirstInvalid == nullptr) {
            // If this block has block data available, some parent was never received, and has no invalid parents, it must be in mapBlocksUnlinked.
            assert(foundInUnlinked);
        }
        if (!(pindex->nStatus & BLOCK_HAVE_DATA)) assert(!foundInUnlinked); // Can't be in mapBlocksUnlinked if we don't HAVE_DATA
        if (pindexFirstMissing == nullptr) assert(!foundInUnlinked); // We aren't missing data for any parent -- cannot be in mapBlocksUnlinked.
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed == nullptr && pindexFirstMissing != nullptr) {
            // We HAVE_DATA for this block, have received data for all parents at some point, but we're currently missing data for some parent.
            assert(fHavePruned); // We must have pruned.
            // This block may have entered mapBlocksUnlinked if:
            //  - it has a descendant that at some point had more work than the
            //    tip, and
            //  - we tried switching to that descendant but were missing
            //    data for some intermediate block between chainActive and the
            //    tip.
            // So if this block is itself better than chainActive.Tip() and it wasn't in
            // setBlockIndexCandidates, then it must be in mapBlocksUnlinked.
            if (!CBlockIndexWorkComparator()(pindex, chainActive.Tip()) && setBlockIndexCandidates.count(pindex) == 0) {
                if (pindexFirstInvalid == nullptr) {
                    assert(foundInUnlinked);
                }
            }
        }
        // assert(pindex->GetBlockHash() == pindex->GetBlockHeader().GetHash()); // Perhaps too slow
        // End: actual consistency checks.

        // Try descending into the first subnode.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> range = forward.equal_range(pindex);
        if (range.first != range.second) {
            // A subnode was found.
            pindex = range.first->second;
            nHeight++;
            continue;
        }
        // This is a leaf node.
        // Move upwards until we reach a node of which we have not yet visited the last child.
        while (pindex) {
            // We are going to either move to a parent or a sibling of pindex.
            // If pindex was the first with a certain property, unset the corresponding variable.
            if (pindex == pindexFirstInvalid) pindexFirstInvalid = nullptr;
            if (pindex == pindexFirstMissing) pindexFirstMissing = nullptr;
            if (pindex == pindexFirstNeverProcessed) pindexFirstNeverProcessed = nullptr;
            if (pindex == pindexFirstNotTreeValid) pindexFirstNotTreeValid = nullptr;
            if (pindex == pindexFirstNotTransactionsValid) pindexFirstNotTransactionsValid = nullptr;
            if (pindex == pindexFirstNotChainValid) pindexFirstNotChainValid = nullptr;
            if (pindex == pindexFirstNotScriptsValid) pindexFirstNotScriptsValid = nullptr;
            // Find our parent.
            CBlockIndex* pindexPar = pindex->pprev;
            // Find which child we just visited.
            std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangePar = forward.equal_range(pindexPar);
            while (rangePar.first->second != pindex) {
                assert(rangePar.first != rangePar.second); // Our parent must have at least the node we're coming from as child.
                rangePar.first++;
            }
            // Proceed to the next one.
            rangePar.first++;
            if (rangePar.first != rangePar.second) {
                // Move to the sibling.
                pindex = rangePar.first->second;
                break;
            } else {
                // Move up further.
                pindex = pindexPar;
                nHeight--;
                continue;
            }
        }
    }

    // Check that we actually traversed the entire map.
    assert(nNodes == forward.size());
}

std::string CBlockFileInfo::ToString() const
{
    return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst, nHeightLast, DateTimeStrFormat("%Y-%m-%d", nTimeFirst), DateTimeStrFormat("%Y-%m-%d", nTimeLast));
}

CBlockFileInfo* GetBlockFileInfo(size_t n)
{
    LOCK(cs_LastBlockFile);

    return &vinfoBlockFile.at(n);
}

ThresholdState VersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsState(chainActive.Tip(), params, pos, versionbitscache);
}

BIP9Stats VersionBitsTipStatistics(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsStatistics(chainActive.Tip(), params, pos);
}

int VersionBitsTipStateSinceHeight(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsStateSinceHeight(chainActive.Tip(), params, pos, versionbitscache);
}

static const uint64_t MEMPOOL_DUMP_VERSION = 1;

bool LoadMempool(void)
{
    const CChainParams& chainparams = Params();
    int64_t nExpiryTimeout = gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60;
    FILE* filestr = fsbridge::fopen(GetDataDir() / "mempool.dat", "rb");
    CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        LogPrintf("Failed to open mempool file from disk. Continuing anyway.\n");
        return false;
    }

    int64_t count = 0;
    int64_t expired = 0;
    int64_t failed = 0;
    int64_t already_there = 0;
    int64_t nNow = GetTime();

    try {
        uint64_t version;
        file >> version;
        if (version != MEMPOOL_DUMP_VERSION) {
            return false;
        }
        uint64_t num;
        file >> num;
        while (num--) {
            CTransactionRef tx;
            int64_t nTime;
            int64_t nFeeDelta;
            file >> tx;
            file >> nTime;
            file >> nFeeDelta;

            CAmount amountdelta = nFeeDelta;
            if (amountdelta) {
                mempool.PrioritiseTransaction(tx->GetHash(), amountdelta);
            }
            CValidationState state;
            if (nTime + nExpiryTimeout > nNow) {
                LOCK(cs_main);
                AcceptToMemoryPoolWithTime(chainparams, mempool, state, tx, nullptr /* pfMissingInputs */, nTime,
                                           nullptr /* plTxnReplaced */, false /* bypass_limits */, 0 /* nAbsurdFee */);
                if (state.IsValid()) {
                    ++count;
                } else {
                    // mempool may contain the transaction already, e.g. from
                    // wallet(s) having loaded it while we were processing
                    // mempool transactions; consider these as valid, instead of
                    // failed, but mark them as 'already there'
                    if (mempool.exists(tx->GetHash())) {
                        ++already_there;
                    } else {
                        ++failed;
                    }
                }
            } else {
                ++expired;
            }
            if (ShutdownRequested())
                return false;
        }
        std::map<uint256, CAmount> mapDeltas;
        file >> mapDeltas;

        for (const auto& i : mapDeltas) {
            mempool.PrioritiseTransaction(i.first, i.second);
        }
    } catch (const std::exception& e) {
        LogPrintf("Failed to deserialize mempool data on disk: %s. Continuing anyway.\n", e.what());
        return false;
    }

    LogPrintf("Imported mempool transactions from disk: %i succeeded, %i failed, %i expired, %i already there\n", count, failed, expired, already_there);
    return true;
}

bool DumpMempool(void)
{
    int64_t start = GetTimeMicros();

    std::map<uint256, CAmount> mapDeltas;
    std::vector<TxMempoolInfo> vinfo;

    {
        LOCK(mempool.cs);
        for (const auto &i : mempool.mapDeltas) {
            mapDeltas[i.first] = i.second;
        }
        vinfo = mempool.infoAll();
    }

    int64_t mid = GetTimeMicros();

    try {
        FILE* filestr = fsbridge::fopen(GetDataDir() / "mempool.dat.new", "wb");
        if (!filestr) {
            return false;
        }

        CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);

        uint64_t version = MEMPOOL_DUMP_VERSION;
        file << version;

        file << (uint64_t)vinfo.size();
        for (const auto& i : vinfo) {
            file << *(i.tx);
            file << (int64_t)i.nTime;
            file << (int64_t)i.nFeeDelta;
            mapDeltas.erase(i.tx->GetHash());
        }

        file << mapDeltas;
        FileCommit(file.Get());
        file.fclose();
        RenameOver(GetDataDir() / "mempool.dat.new", GetDataDir() / "mempool.dat");
        int64_t last = GetTimeMicros();
        LogPrintf("Dumped mempool: %gs to copy, %gs to dump\n", (mid-start)*MICRO, (last-mid)*MICRO);
    } catch (const std::exception& e) {
        LogPrintf("Failed to dump mempool: %s. Continuing anyway.\n", e.what());
        return false;
    }
    return true;
}

void LoadBMMCache()
{
    fs::path path = GetDataDir() / "bmm.dat";
    CAutoFile filein(fsbridge::fopen(path, "rb"), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        return;
    }

    std::vector<uint256> vHashWithdrawal;
    std::vector<uint256> vHashBMM;
    std::vector<uint256> vDepositTXID;
    try {
        int nVersionRequired, nVersionThatWrote;
        filein >> nVersionRequired;
        filein >> nVersionThatWrote;
        if (nVersionRequired > CLIENT_VERSION) {
            return;
        }

        int nWithdrawal = 0;
        filein >> nWithdrawal;
        for (int i = 0; i < nWithdrawal; i++) {
            uint256 hash;
            filein >> hash;
            vHashWithdrawal.push_back(hash);
        }
        int nBMM = 0;
        filein >> nBMM;
        for (int i = 0; i < nBMM; i++) {
            uint256 hash;
            filein >> hash;
            vHashBMM.push_back(hash);
        }
        int nDeposit = 0;
        filein >> nDeposit;
        for (int i = 0; i < nDeposit; i++) {
            uint256 hash;
            filein >> hash;
            vDepositTXID.push_back(hash);
        }
    }
    catch (const std::exception& e) {
        LogPrintf("%s: Error reading BMM cache: %s", __func__, e.what());
        return;
    }

    for (const uint256& u : vHashWithdrawal) {
        bmmCache.StoreBroadcastedWithdrawalBundle(u);
    }
    for (const uint256& u : vHashBMM) {
        bmmCache.CacheVerifiedBMM(u);
    }
    for (const uint256& u : vDepositTXID) {
        bmmCache.CacheVerifiedDeposit(u);
    }
}

void DumpBMMCache()
{
    std::vector<uint256> vHashWithdrawal = bmmCache.GetBroadcastedWithdrawalBundleCache();
    std::vector<uint256> vHashBMM = bmmCache.GetVerifiedBMMCache();
    std::vector<uint256> vDepositTXID = bmmCache.GetVerifiedDepositCache();

    int nWithdrawal = vHashWithdrawal.size();
    int nBMM = vHashBMM.size();
    int nDeposit = vDepositTXID.size();

    fs::path path = GetDataDir() / "bmm.dat.new";
    CAutoFile fileout(fsbridge::fopen(path, "wb"), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        return;
    }

    try {
        fileout << 160000; // version required to read: 0.16.00 or later
        fileout << CLIENT_VERSION; // version that wrote the file

        // Broadcasted Withdrawal Bundle hash cache
        fileout << nWithdrawal; // Number of Withdrawal Bundle hashes in file
        for (const uint256& u : vHashWithdrawal) {
            fileout << u;
        }
        // Verified BMM hash cache
        fileout << nBMM; // Number of Withdrawal Bundle hashes in file
        for (const uint256& u : vHashBMM) {
            fileout << u;
        }

        // Verified deposit txid cache
        fileout << nDeposit; // Number of Withdrawal Bundle hashes in file
        for (const uint256& u : vDepositTXID) {
            fileout << u;
        }

    }
    catch (const std::exception& e) {
        LogPrintf("%s: Error writing BMM cache: %s", __func__, e.what());
        return;
    }

    FileCommit(fileout.Get());
    fileout.fclose();
    RenameOver(GetDataDir() / "bmm.dat.new", GetDataDir() / "bmm.dat");

    LogPrintf("%s: Wrote BMM cache.\n", __func__);
}

void LoadMainBlockCache()
{
    fs::path path = GetDataDir() / "mainblockhash.dat";
    CAutoFile filein(fsbridge::fopen(path, "rb"), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        return;
    }

    std::vector<uint256> vHash;
    try {
        int nVersionRequired, nVersionThatWrote;
        filein >> nVersionRequired;
        filein >> nVersionThatWrote;
        if (nVersionRequired > CLIENT_VERSION) {
            return;
        }

        int count = 0;
        filein >> count;
        for (int i = 0; i < count; i++) {
            uint256 hash;
            filein >> hash;
            vHash.push_back(hash);
        }
    }
    catch (const std::exception& e) {
        LogPrintf("%s: Error reading main block cache: %s", __func__, e.what());
        return;
    }

    for (const uint256& u : vHash)
        bmmCache.CacheMainBlockHash(u);
}

void DumpMainBlockCache()
{
    std::vector<uint256> vHash = bmmCache.GetMainBlockHashCache();
    if (vHash.empty())
        return;

    int count = vHash.size();

    fs::path path = GetDataDir() / "mainblockhash.dat.new";
    CAutoFile fileout(fsbridge::fopen(path, "wb"), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        return;
    }

    try {
        fileout << 160000; // version required to read: 0.16.00 or later
        fileout << CLIENT_VERSION; // version that wrote the file
        fileout << count; // Number of Withdrawal Bundle hashes in file

        for (const uint256& u : vHash) {
            fileout << u;
        }
    }
    catch (const std::exception& e) {
        LogPrintf("%s: Error writing main block cache: %s", __func__, e.what());
        return;
    }

    FileCommit(fileout.Get());
    fileout.fclose();
    RenameOver(GetDataDir() / "mainblockhash.dat.new", GetDataDir() / "mainblockhash.dat");

    LogPrintf("%s: Wrote %u\n", __func__, count);
}

void DumpWithdrawalIDCache()
{
    std::set<uint256> setWithdrawalID = bmmCache.GetCachedWithdrawalID();
    if (setWithdrawalID.empty())
        return;

    int count = setWithdrawalID.size();

    fs::path path = GetDataDir() / "withdrawalid.dat.new";
    CAutoFile fileout(fsbridge::fopen(path, "wb"), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        return;
    }

    try {
        fileout << 160000; // version required to read: 0.16.00 or later
        fileout << CLIENT_VERSION; // version that wrote the file
        fileout << count; // Number of Withdrawal IDs in file

        for (const uint256& u : setWithdrawalID) {
            fileout << u;
        }
    }
    catch (const std::exception& e) {
        LogPrintf("%s: Error writing Withdrawal ID cache: %s", __func__, e.what());
        return;
    }

    FileCommit(fileout.Get());
    fileout.fclose();
    RenameOver(GetDataDir() / "withdrawalid.dat.new", GetDataDir() / "withdrawalid.dat");

    LogPrintf("%s: Wrote %u\n", __func__, count);
}

void LoadWithdrawalIDCache()
{
    fs::path path = GetDataDir() / "withdrawalid.dat";
    CAutoFile filein(fsbridge::fopen(path, "rb"), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        return;
    }

    std::vector<uint256> vWithdrawalID;
    try {
        int nVersionRequired, nVersionThatWrote;
        filein >> nVersionRequired;
        filein >> nVersionThatWrote;
        if (nVersionRequired > CLIENT_VERSION) {
            return;
        }

        int count = 0;
        filein >> count;
        for (int i = 0; i < count; i++) {
            uint256 id;
            filein >> id;
            vWithdrawalID.push_back(id);
        }
    }
    catch (const std::exception& e) {
        LogPrintf("%s: Error reading Withdrawal ID cache: %s", __func__, e.what());
        return;
    }

    for (const uint256& u : vWithdrawalID)
        bmmCache.CacheWithdrawalID(u);
}

/** Create joined Withdrawal Bundle to be sent to the mainchain */
bool CreateWithdrawalBundleTx(int nHeight, CTransactionRef& withdrawalBundleTx, CTransactionRef& withdrawalBundleDataTx, bool fReplicationCheck, bool fCheckUnique)
{
    unsigned int nMinWithdrawal = gArgs.GetArg("-minwithdrawal", DEFAULT_MIN_WITHDRAWAL_CREATE_BUNDLE);

    // Load the latest Withdrawal Bundle
    bool fHaveWithdrawalBundles = false;
    uint256 hashLatestWithdrawalBundle;
    SidechainWithdrawalBundle withdrawalBundleLatest;
    psidechaintree->GetLastWithdrawalBundleHash(hashLatestWithdrawalBundle);
    if (psidechaintree->GetWithdrawalBundle(hashLatestWithdrawalBundle, withdrawalBundleLatest)) {
        fHaveWithdrawalBundles = true;
    }

    // If the last Withdrawal Bundle failed - wait Withdrawal_FAIL_WAIT_PERIOD blocks before creating
    // a new one.
    if (fHaveWithdrawalBundles && withdrawalBundleLatest.status == WITHDRAWAL_BUNDLE_FAILED) {
        if (nHeight - withdrawalBundleLatest.nFailHeight < WITHDRAWAL_BUNDLE_FAIL_WAIT_PERIOD) {
            LogPrintf("%s: Not enough blocks since last failed Withdrawal Bundle!\n", __func__);
            return false;
        }
    }

    if (!fReplicationCheck) {
        if (fHaveWithdrawalBundles) {
            if (withdrawalBundleLatest.status == WITHDRAWAL_BUNDLE_CREATED) {
                LogPrintf("%s: Current Withdrawal Bundle for this sidechain still pending!\n", __func__);
                return false;
            }
            // Check for existing Withdrawal Bundle in mainchain SCDB for this sidechain
            SidechainClient client;
            std::vector<uint256> vHashWithdrawalBundle;
            if (client.ListWithdrawalBundleStatus(vHashWithdrawalBundle)) {
                LogPrintf("%s: Mainchain SCDB already tracking Withdrawal Bundle for this sidechain\n", __func__);
                return false;
            }
        }
    }

    // Get Withdrawal(s) from psidechaintree
    std::vector<SidechainWithdrawal> vWithdrawal = psidechaintree->GetWithdrawals(THIS_SIDECHAIN);
    if (vWithdrawal.empty()) {
        LogPrintf("%s: No withdrawals(s) to create bundle!\n", __func__);
        return false;
    }

    // Select only Withdrawals with Withdrawal_UNSPENT status
    SelectUnspentWithdrawal(vWithdrawal);

    // Sort Withdrawals by mainchain fee amount
    SortWithdrawalByFee(vWithdrawal);

    if (!fReplicationCheck && vWithdrawal.size() < nMinWithdrawal) {
        LogPrintf("%s: Not enough Withdrawal(s) to create Withdrawal Bundle\n", __func__);
        return false;
    }

    // Withdrawal Bundle database object for psidechaintree (sidechain only)
    SidechainWithdrawalBundle withdrawalBundle;
    withdrawalBundle.nSidechain = THIS_SIDECHAIN;

    CMutableTransaction wjtx; // Withdrawal Bundle

    // Bundle wire format is a per-network consensus rule (see CUSFBundleFormat):
    // - legacy: vout[0] = OP_RETURN "D" marker, vout[1] = fee (LE), payouts after
    // - CUSF:   vout[0] = OP_RETURN PUSH8(fee BE), payouts after (BlindedM6)
    const bool fCUSF = UseCUSFBundleFormat();

    CAmount amountMainchainFees = 0;
    if (fCUSF) {
        // Fee output placeholder at vout[0] (final size already; updated later)
        wjtx.vout.push_back(CTxOut(0, EncodeWithdrawalFeesCUSF(0)));
    } else {
        // Add SIDECHAIN_WITHDRAWAL_BUNDLE_RETURN_DEST OP_RETURN output
        wjtx.vout.push_back(CTxOut(0, CScript() << OP_RETURN << ParseHex(HexStr(SIDECHAIN_WITHDRAWAL_BUNDLE_RETURN_DEST))));

        // Add a dummy output for mainchain fee encoding (updated later)
        wjtx.vout.push_back(CTxOut(0, CScript() << OP_RETURN << CScriptNum(1LL << 40)));
    }

    wjtx.nVersion = 2;
    wjtx.vin.resize(1); // Dummy vin for serialization...
    wjtx.vin[0].scriptSig = CScript() << OP_0;
    for (const SidechainWithdrawal& withdrawal : vWithdrawal) {
        CAmount amountWithdrawal = withdrawal.amount - withdrawal.mainchainFee;

        amountMainchainFees += withdrawal.mainchainFee;

        // TODO check IsValidDestination
        // Output to mainchain keyID
        CTxDestination dest = DecodeDestination(withdrawal.strDestination, true /* fMainchain */);
        wjtx.vout.push_back(CTxOut(amountWithdrawal, GetScriptForDestination(dest)));

        // Add Withdrawal objid to Withdrawal Bundle obj
        withdrawalBundle.vWithdrawalID.push_back(withdrawal.GetID());

        // Make sure we have room for more outputs
        if (GetTransactionWeight(wjtx) > MAX_WITHDRAWAL_BUNDLE_WEIGHT) {
            // If we went over size, undo this output and stop
            withdrawalBundle.vWithdrawalID.pop_back();
            wjtx.vout.pop_back();

            // Also remove added fees
            amountMainchainFees -= withdrawal.mainchainFee;

            break;
        }
    }

    // Update mainchain fee encoding output.
    if (fCUSF)
        wjtx.vout[0].scriptPubKey = EncodeWithdrawalFeesCUSF(amountMainchainFees);
    else
        wjtx.vout[1].scriptPubKey = EncodeWithdrawalFees(amountMainchainFees);

    // Did anything make it into the Withdrawal Bundle?
    if (!wjtx.vout.size()) {
        LogPrintf("%s: ERROR: Withdrawal Bundle empty!\n", __func__);
        return false;
    }

    // If the Withdrawal Bundle hash will be the same as a previous Withdrawal Bundle return false. It is
    // possible for a new Withdrawal Bundle to have the same hash as a previous Withdrawal Bundle if all of
    // the outputs (destinations & amounts) are exactly the same. In that case,
    // wait for a new Withdrawal to be added to the database so that this Withdrawal Bundle will have
    // a unique hash. It would also be possible to remove one of the outputs to
    // obtain a unique Withdrawal Bundle hash (TODO?)
    if (fCheckUnique && psidechaintree->HaveWithdrawalBundle(wjtx.GetHash())) {
        LogPrintf("%s: ERROR: Withdrawal Bundle is not unique!\n", __func__);
        return false;
    }

    // Check that the Withdrawal Bundle is valid by mainchain policy
    CFeeRate dust = CFeeRate(DUST_RELAY_TX_FEE);
    std::string strReason = "";
    if (!CoreIsStandardTx(wjtx, true, dust, strReason)) {
        LogPrintf("%s: ERROR: Withdrawal Bundle failed core standardness tests! Reason: %s\n", __func__, strReason);
        return false;
    }

    // Add Withdrawal Bundle transaction to the Withdrawal Bundle database object
    withdrawalBundle.tx = wjtx;

    // Return the Withdrawal Bundle transaction itself by reference
    withdrawalBundleTx = MakeTransactionRef(wjtx);

    // Output data
    CMutableTransaction mtx;
    mtx.vout.push_back(CTxOut(0, withdrawalBundle.GetScript()));

    // Return the Withdrawal Bundle data transaction by reference
    withdrawalBundleDataTx = MakeTransactionRef(mtx);

    LogPrintf("%s: Withdrawal Bundle created! Hash: %s\n", __func__, wjtx.GetHash().ToString());
    return true;
}

bool VerifyWithdrawalBundles(std::string& strFail, int nHeight, const std::vector<CTransactionRef>& vtx, std::vector<SidechainWithdrawal>& vWithdrawal, uint256& hashWithdrawalBundle, uint256& hashWithdrawalBundleID, bool fReplicate) {
    // Keep track of how many Withdrawal Bundle(s) are in the block, only 1 is allowed
    int nWithdrawalBundle = 0;

    // Loop through the blocks txns and look for Withdrawal Bundle(s) to verify
    CAmount amountMainchainFees = 0;
    for (const CTransactionRef& tx : vtx) {
        for (const CTxOut& txout : tx->vout) {
            const CScript& scriptPubKey = txout.scriptPubKey;

            std::vector<unsigned char> vch;
            if (!scriptPubKey.IsSidechainObj(vch))
                continue;

            SidechainObj *obj = ParseSidechainObj(vch);
            if (!obj)  {
                strFail = "Invalid sidechain obj!\n";
                return false;
            }

            if (obj->sidechainop != DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP)
                continue;

            nWithdrawalBundle++;
            if (nWithdrawalBundle > 1) {
                strFail = "Invalid Withdrawal Bundle - multiple in block!\n";
                return false;
            }

            const SidechainWithdrawalBundle *withdrawalBundle = (const SidechainWithdrawalBundle *) obj;

            // Check that every Withdrawal this Withdrawal Bundle has listed is in the db
            // and verify the status is not spent.
            for (const uint256& id : withdrawalBundle->vWithdrawalID) {
                SidechainWithdrawal withdrawal;

                if (!psidechaintree->GetWithdrawal(id, withdrawal)) {
                    strFail = "Invalid withdrawal - does not exist!\n";
                    return false;
                }
                if (withdrawal.status != WITHDRAWAL_UNSPENT) {
                    strFail = "Invalid withdrawal - spent!\n";
                    return false;
                }

                amountMainchainFees += withdrawal.mainchainFee;

                vWithdrawal.push_back(withdrawal);
            }

            // Data outputs by network bundle format: legacy = return-dest
            // marker + fee output; CUSF = fee output only (BlindedM6).
            const bool fCUSF = UseCUSFBundleFormat();
            const size_t nDataOutputs = fCUSF ? 1 : 2;

            // Check that there are actually enough outputs for this to be valid
            if (withdrawalBundle->tx.vout.size() < nDataOutputs + 1) {
                strFail = "Invalid Withdrawal Bundle - too few outputs!\n";
                return false;
            }

            // Check that the number of outputs equals the number of
            // Withdrawal(s) listed in the Withdrawal Bundle + the encoded data
            // output(s) for this network's bundle format
            if (withdrawalBundle->tx.vout.size() != vWithdrawal.size() + nDataOutputs) {
                strFail = "Invalid Withdrawal Bundle - missing / extra outputs!\n";
                return false;
            }

            // Check that the amount in the encoded mainchain fee output is
            // equal to the sum of fees from the withdrawals
            CAmount amountRead = 0;
            const CScript& scriptFee = withdrawalBundle->tx.vout[fCUSF ? 0 : 1].scriptPubKey;
            if (!(fCUSF ? DecodeWithdrawalFeesCUSF(scriptFee, amountRead)
                        : DecodeWithdrawalFees(scriptFee, amountRead))) {
                strFail = "Invalid Withdrawal Bundle - failed to decode mainchain fee output!\n";
                return false;
            }

            if (amountRead != amountMainchainFees) {
                strFail = "Invalid Withdrawal Bundle - invalid encoded mainchain fee output!\n";
                return false;
            }

            // Check that every Withdrawal listed in the Withdrawal Bundle is included
            for (const SidechainWithdrawal& w : vWithdrawal) {
                bool fFound = false;
                for (const CTxOut& out : withdrawalBundle->tx.vout) {
                    if (out.nValue == w.amount - w.mainchainFee &&
                            GetScriptForDestination(DecodeDestination(w.strDestination, true)) == out.scriptPubKey) {
                        fFound = true;
                        break;
                    }
                }
                if (!fFound) {
                    strFail = "Invalid Withdrawal Bundle - missing output!\n";
                    return false;
                }
            }

            // Check if standard by mainchain bitcoin core standards
            CFeeRate dust = CFeeRate(DUST_RELAY_TX_FEE);
            std::string strReason = "";
            if (!CoreIsStandardTx(withdrawalBundle->tx, true, dust, strReason)) {
                strFail = "Invalid Withdrawal Bundle - failed CoreIsStandardTx!\n";
                return false;
            }

            // Check Withdrawal Bundle weight
            if (GetTransactionWeight(withdrawalBundle->tx) > MAX_WITHDRAWAL_BUNDLE_WEIGHT) {
                strFail = "Invalid Withdrawal Bundle - too large!\n";
                return false;
            }

            // Verify that we can replicate this Withdrawal Bundle if fReplicate is set
            if (fReplicate) {
                // Try to create the same Withdrawal Bundle
                CTransactionRef withdrawalBundleTx;
                CTransactionRef withdrawalBundleDataTx;
                if (!CreateWithdrawalBundleTx(nHeight, withdrawalBundleTx, withdrawalBundleDataTx, true /* fReplicationCheck */ )) {
                    strFail = "Invalid Withdrawal Bundle - failed to create replicant Withdrawal Bundle!\n";
                    return false;
                }
                // Verify that our Withdrawal Bundle matches the one in this block
                if (*withdrawalBundleTx != CTransaction(withdrawalBundle->tx)) {
                    strFail = "Invalid Withdrawal Bundle - replicated Withdrawal Bundle does not match!\n";
                    return false;
                }
            }

            hashWithdrawalBundle = withdrawalBundle->tx.GetHash();
            hashWithdrawalBundleID = withdrawalBundle->GetID();

            // Update the status of withdrawals included in the Withdrawal Bundle - returned by
            // reference and applied to the DB if needed
            for (size_t i = 0; i < vWithdrawal.size(); i++)
                vWithdrawal[i].status = WITHDRAWAL_IN_BUNDLE;
        }
    }
    if (!hashWithdrawalBundle.IsNull()) {
        std::string strReplicated = fReplicate ? "true" : "false";
        LogPrintf("%s Verified Withdrawal Bundle: %s.\n Replicated? %s\n", __func__, hashWithdrawalBundle.ToString(), strReplicated);
    }
    return true;
}

bool SortDeposits(const std::vector<SidechainDeposit>& vDeposit, std::vector<SidechainDeposit>& vDepositSorted)
{
    if (vDeposit.empty())
        return true;

    if (vDeposit.size() == 1) {
        vDepositSorted = vDeposit;
        return true;
    }

    // Find the first deposit in the list by looking for the deposit which
    // spends a CTIP not in the list. There can only be one. We are also going
    // to check that there is only one missing CTIP input here.
    int nMissingCTIP = 0;
    for (size_t x = 0; x < vDeposit.size(); x++) {
        const SidechainDeposit dx = vDeposit[x];

        // Look for the input of this deposit
        bool fFound = false;
        for (size_t y = 0; y < vDeposit.size(); y++) {
            const SidechainDeposit dy = vDeposit[y];

            // The CTIP output of the deposit that might be the input
            const COutPoint prevout(dy.dtx.GetHash(), dy.nBurnIndex);

            // Look for the CTIP output
            for (const CTxIn& in : dx.dtx.vin) {
                if (in.prevout == prevout) {
                    fFound = true;
                    break;
                }
            }
            if (fFound)
                break;
        }

        // If we didn't find the CTIP input, this should be the first and only
        // deposit without one.
        if (!fFound) {
            nMissingCTIP++;
            if (nMissingCTIP > 1) {
                LogPrintf("%s: Error: Multiple missing CTIP!\n", __func__);
                return false;
            }
            // Add the first deposit to the result
            vDepositSorted.push_back(dx);
            // We found the first deposit but do not stop the loop here
            // because we are also checking to make sure there aren't any
            // other deposits missing a CTIP input from the list.
        }
    }

    // Now that we know which deposit is first in the list we can add the rest
    // in CTIP spend order.

    if (vDepositSorted.empty()) {
        LogPrintf("%s: Error: Coult not find first deposit in list!\n", __func__);
        return false;
    }

    // Track the CTIP output of the latest deposit we have sorted
    COutPoint prevout(vDepositSorted.back().dtx.GetHash(), vDepositSorted.back().nBurnIndex);

    // Look for the deposit that spends the last sorted CTIP output and sort it.
    // If we cannot find a deposit spending the CTIP, that should mean we
    // reached the end of sorting.
    std::vector<SidechainDeposit>::const_iterator it = vDeposit.begin();
    while (it != vDeposit.end()) {
        bool fFound = false;
        for (const CTxIn& in : it->dtx.vin) {
            if (in.prevout == prevout) {
                // Add the sorted deposit to the list
                vDepositSorted.push_back(*it);

                // Update the CTIP output we are looking for
                const SidechainDeposit deposit = vDepositSorted.back();
                prevout = COutPoint(deposit.dtx.GetHash(), deposit.nBurnIndex);

                // Start from begin() again
                fFound = true;
                it = vDeposit.begin();

                break;
            }
        }
        if (!fFound)
            it++;
    }

    if (vDeposit.size() != vDepositSorted.size()) {
        LogPrintf("%s: Error: Invalid result size! In: %u Out: %u\n", __func__,
                vDeposit.size(), vDepositSorted.size());
        return false;
    }

    // Double check proper CTIP UTXO ordering.
    // Loop backwards keeping track of the previous value and verify that the
    // r-next item in the vector is the CTIP input for the previous value.
    std::vector<SidechainDeposit>::const_reverse_iterator rit;
    rit = vDepositSorted.rbegin();
    SidechainDeposit prev;
    for (; rit != vDepositSorted.rend(); rit++) {
        // For the last element in the list we track the value and move on
        if (rit == vDepositSorted.rbegin())  {
            prev = *rit;
            continue;
        }

        // Check if the r-next item is the CTIP for the previous deposit
        bool fFound = false;
        for (const CTxIn& in : prev.dtx.vin) {
            if (in.prevout.hash == rit->dtx.GetHash()
                && rit->dtx.vout.size() > in.prevout.n
                && rit->nBurnIndex == in.prevout.n) {
                fFound = true;
                break;
            }
        }
        if (!fFound) {
            LogPrintf("%s: Error: Deposit in sorted list (not first) missing CTIP! Deposit: \n%s\n", __func__, rit->ToString());
            return false;
        }
        // Update the previous object to this index before moving to r-next
        prev = *rit;
    }

    return true;
}

bool CheckMainchainConnection()
{
    SidechainClient client;

    int nMainchainBlocks = 0;
    if (!client.GetBlockCount(nMainchainBlocks)) {
        LogPrintf("%s: Mainchain connection not detected!\n", __func__);
        return false;
    }

    return true;
}

void SetNetworkActive(bool fActive, const std::string& strReason)
{
    if (!g_connman)
        return;

    bool fCurrentState = g_connman->GetNetworkActive();
    if (fActive == fCurrentState)
        return;

    g_connman->SetNetworkActive(fActive);

    LogPrintf("%s: Network activity set to: %s\n", __func__, fActive ? "Enabled" : "Disabled");
    if (strReason.size()) {
        LogPrintf("Reason for network activity change: %s\n", strReason);
    }

    if (!fActive) {
        LogPrintf("If you are using the GUI please follow prompts on screen about mainchain connection!\n");
        LogPrintf("If you are running the daemon check mainchain & sidechain configuration files.\n");
        LogPrintf("To retry connection, use the 'refreshbmm' RPC command.\n");
    }
}

//! Mainchain hashes requested per ancestor batch during a header-cache walk.
//! The enforcer answers a batch in a single call, so this is the difference
//! between one request per block and one per thousand.
static const uint32_t MAIN_BLOCK_CACHE_BATCH = 1000;

bool UpdateMainBlockHashCache(bool& fReorg, std::vector<uint256>& vDisconnected)
{
    std::lock_guard<std::mutex> lock(mainBlockCacheMutex);

    //
    // Note: bitcoin core does not count genesis block towards block count but
    // we will cache it.
    //

    SidechainClient client;

    // Get the current mainchain block height
    int nMainBlocks = 0;
    if (!client.GetBlockCount(nMainBlocks)) {
        LogPrintf("%s: Failed to update - cannot get block count from mainchain. (connection issue?)\n", __func__);
        return false;
    }

    uint256 hashMainTip;
    if (!client.GetBlockHash(nMainBlocks, hashMainTip)) {
        LogPrintf("%s: Failed to get to mainchain tip block hash!\n", __func__);
        return false;
    }

    uint256 hashCachedTip = bmmCache.GetLastMainBlockHash();

    // If the block height hasn't changed, check that if cached chain tip is the
    // same as the current mainchain tip. If it is we don't need to do anything
    // else. If it isn't we will continue to update / reorg handling.
    int nCachedBlocks = bmmCache.GetCachedBlockCount();
    if (nMainBlocks + 1 == nCachedBlocks && hashCachedTip == hashMainTip) {
        return true;
    }

    // Otherwise;
    // From the new mainchain tip, start walking back through mainchain blocks
    // while keeping track of them in order until we find one that connects to
    // one of our cached blocks by prevblock.
    //
    // The walk is BATCHED (see L1Client::GetAncestorHashes): asking each
    // transport for a run of ancestors at a time, rather than one hash per
    // call. On the enforcer transport a per-block walk is quadratic - every
    // GetBlockHash() re-walks from the tip - which made a cold sync of a few
    // thousand blocks take the better part of an hour.
    uint256 hashPrevBlock;
    std::deque<uint256> deqHashNew;
    std::vector<uint256> vBatch;
    size_t nBatchPos = 0;
    uint256 hashCursor = hashMainTip;
    int nCursor = nMainBlocks;
    for (int i = nMainBlocks; i > 0; i--) {
        // Refill the batch when exhausted. The batch starts AT the cursor
        // block, so skip its first entry (already consumed as the cursor).
        if (nBatchPos >= vBatch.size()) {
            if (!client.GetAncestorHashes(hashCursor, nCursor, MAIN_BLOCK_CACHE_BATCH, vBatch) || vBatch.size() < 2) {
                LogPrintf("%s: Failed to get to mainchain block: %u\n", __func__, i - 1);
                return false;
            }
            nBatchPos = 1;
        }

        hashPrevBlock = vBatch[nBatchPos++];

        // Advance the cursor to the oldest hash consumed so the next refill
        // continues from there.
        hashCursor = hashPrevBlock;
        nCursor = i - 1;

        // Check if the prevblock is in our cache. Once we find a prevblock in
        // our cache we can update our cache from that block up to the new
        // mainchain tip.
        if (bmmCache.HaveMainBlock(hashPrevBlock)) {
            deqHashNew.push_front(hashPrevBlock);
            break;
        }

        deqHashNew.push_front(hashPrevBlock);
    }
    // Also add the new mainchain tip
    deqHashNew.push_back(hashMainTip);

    return bmmCache.UpdateMainBlockCache(deqHashNew, fReorg, vDisconnected);
}

bool VerifyMainBlockCache(std::string& strError)
{
    SidechainClient client;

    const std::vector<uint256> vHash = bmmCache.GetMainBlockHashCache();
    if (!vHash.size()) {
        strError = "No mainchain blocks in cache!";
        return false;
    }

    // Compare cached hash at height with mainchain block hash at height
    for (size_t i = 0; i < vHash.size(); i++) {
        uint256 hashBlock;

        if (!client.GetBlockHash(i, hashBlock)) {
            strError = "Failed to request mainchain block hash!";
            return false;
        }

        if (hashBlock != vHash[i]) {
            strError = "Invalid hash cached: ";
            strError += vHash[i].ToString();
            strError += " height: ";
            strError += std::to_string(i);

            return false;
        }
    }

    return true;
}

void HandleMainchainReorg(const std::vector<uint256>& vOrphan)
{
    std::lock_guard<std::mutex> lock(mainBlockCacheReorgMutex);

    // For mainchain blocks that were orphaned - invalidate bmm blocks with
    // commitments from them.
    //
    // vOrphan contains a list of mainchain block hashes that were orphaned

    // Before invalidating any blocks, check the sanity of the mainchain block
    // cache and then verify that the blocks to be orphaned actually are missing
    // from the mainchain.

    // Check the mainchain block cache
    std::string strError = "";
    if (!VerifyMainBlockCache(strError)) {
        LogPrintf("%s: Main block cache invalid: %s. Resyncing...\n",
                __func__, strError);
        // Reset the mainchain block cache and then re-sync it
        bmmCache.ResetMainBlockCache();

        // TODO
        // If during this call a reorg is detected and we have more orphans then
        // something bad happened and needs to be handled. Since we just reset
        // the mainchain block cache, have a mutex lock, and are updating the
        // cache from scratch now, it should be impossible.
        bool fReorg = false;
        std::vector<uint256> vOrphanIgnore;
        if (!UpdateMainBlockHashCache(fReorg, vOrphanIgnore)) {
            // TODO
            // If we make it to this point there might be a connection issue or
            // something going on. Maybe the mainchain node went down during the
            // function? There might be something better to do than just logging
            // the error here.
            LogPrintf("%s: Failed to re-update main block cache after reset!",
                    __func__);
            return;
        }
    }

    // Check that the alleged orphans actually don't exist on the mainchain
    std::vector<uint256> vOrphanFinal;
    for (const uint256& u : vOrphan) {
        if (!bmmCache.HaveMainBlock(u))
            vOrphanFinal.push_back(u);
    }

    // Check if any BMM blocks were created from commitments in this
    // orphaned mainchain block
    for (const uint256& u : vOrphanFinal) {
        CValidationState state;
        {
            LOCK(cs_main);
            // Check our map of blocks based on their mainchain BMM commit block
            if (!mapBlockMainHashIndex.count(u))
                continue;

            CBlockIndex* pindex = mapBlockMainHashIndex[u];
            if (!chainActive.Contains(pindex))
                continue;

            InvalidateBlock(state, Params(), pindex);

            LogPrintf("%s: Invalidated block: %s because mainchain block: %s was orphaned!\n",
                    __func__, pindex->GetBlockHash().ToString(), u.ToString());

            if (!state.IsValid()) {
                LogPrintf("%s: Error while invalidating blocks: %s\n",
                        __func__, FormatStateMessage(state));
                return;
            }
        }

        ActivateBestChain(state, Params());
        if (!state.IsValid()) {
            LogPrintf("%s: Error activating best chain: %s\n",
                    __func__, FormatStateMessage(state));
            return;
        }
    }
}

CScript EncodeWithdrawalFees(const CAmount& amount)
{
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    s << amount;

    CScript script;
    script << OP_RETURN;
    script << std::vector<unsigned char>(s.begin(), s.end());

    return script;
}

bool DecodeWithdrawalFees(const CScript& script, CAmount& amount)
{
    if (script[0] != OP_RETURN || script.size() != 10) {
        LogPrintf("%s: Error: Invalid script!\n", __func__);
        return false;
    }

    CScript::const_iterator it = script.begin() + 1;
    std::vector<unsigned char> vch;
    opcodetype opcode;

    if (!script.GetOp(it, opcode, vch)) {
        LogPrintf("%s: Error: GetOp failed!\n", __func__);
        return false;
    }

    if (vch.empty()) {
        LogPrintf("%s: Error: Amount bytes empty!\n", __func__);
        return false;
    }

    if (vch.size() > 8) {
        LogPrintf("%s: Error: Amount bytes too large!\n", __func__);
        return false;
    }

    try {
        CDataStream ds(vch, SER_NETWORK, PROTOCOL_VERSION);
        ds >> amount;
    } catch (const std::exception&) {
        LogPrintf("%s: Error: Failed to deserialize amount!\n", __func__);
        return false;
    }

    return true;
}

bool UseCUSFBundleFormat()
{
    if (Params().CUSFBundleFormat())
        return true;

    // Bench/test override: regtest only, so a stray flag can never fork a
    // public network (init refuses it elsewhere).
    return Params().NetworkIDString() == CBaseChainParams::REGTEST &&
        gArgs.GetBoolArg("-cusfbundleformat", false);
}

CScript EncodeWithdrawalFeesCUSF(const CAmount& amount)
{
    // The enforcer's BlindedM6 requires vout[0] to be exactly
    // OP_RETURN PUSH8(fee) with the fee in BIG-endian byte order
    // (bip300301_enforcer lib/types.rs BlindedM6::try_from).
    std::vector<unsigned char> vch(8, 0);
    uint64_t n = (uint64_t)amount;
    for (int i = 7; i >= 0; i--) {
        vch[i] = n & 0xff;
        n >>= 8;
    }

    CScript script;
    script << OP_RETURN;
    script << vch;
    return script;
}

bool DecodeWithdrawalFeesCUSF(const CScript& script, CAmount& amount)
{
    // Expect exactly: OP_RETURN PUSH8 <8 bytes big-endian>
    if (script.size() != 10 || script[0] != OP_RETURN)
        return false;

    CScript::const_iterator it = script.begin() + 1;
    std::vector<unsigned char> vch;
    opcodetype opcode;
    if (!script.GetOp(it, opcode, vch))
        return false;

    if (vch.size() != 8)
        return false;

    uint64_t n = 0;
    for (int i = 0; i < 8; i++)
        n = (n << 8) | vch[i];

    // A mainchain fee cannot exceed the money range
    if (n > (uint64_t)MAX_MONEY)
        return false;

    amount = (CAmount)n;
    return true;
}

uint256 GetWithdrawalRefundMessageHash(const uint256& id)
{
    // Standard format of refund request message
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strRefundMessageMagic;
    ss << id.ToString();

    return ss.GetHash();
}

//! Guess how far we are in the verification process at the given block index
//! require cs_main if pindex has not been validated yet (because nChainTx might be unset)
double GuessVerificationProgress(const ChainTxData& data, const CBlockIndex *pindex) {
    if (pindex == nullptr)
        return 0.0;

    int64_t nNow = time(nullptr);

    double fTxTotal;

    if (pindex->nChainTx <= data.nTxCount) {
        fTxTotal = data.nTxCount + (nNow - data.nTime) * data.dTxRate;
    } else {
        fTxTotal = pindex->nChainTx + (nNow - pindex->GetBlockTime()) * data.dTxRate;
    }

    return pindex->nChainTx / fTxTotal;
}

class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup() {
        // block headers
        BlockMap::iterator it1 = mapBlockIndex.begin();
        for (; it1 != mapBlockIndex.end(); it1++)
            delete (*it1).second;
        mapBlockIndex.clear();
        mapBlockMainHashIndex.clear();
    }
} instance_of_cmaincleanup;
