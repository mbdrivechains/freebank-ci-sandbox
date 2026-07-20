// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pool.h>

#include <bill.h>           // BillHashOutputs
#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <house.h>
#include <key.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <txdb.h>
#include <undo.h>
#include <util.h>
#include <version.h>

#include <functional>

#include <boost/test/unit_test.hpp>

// Contextual pool-op validator (validation.cpp, external linkage; not in a
// public header). Forward-declared so the priors/house/formula gates can be
// exercised directly, asserting exact reject reasons.
bool CheckPoolOperation(const CTransaction& tx, CValidationState& state, int nHeight,
                        const std::function<bool(uint32_t, CPool&)>& fnGetPool,
                        const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                        CPool& poolOut, CHouse& houseOut, bool& fHouseChanged, bool& fPoolRetired);

BOOST_FIXTURE_TEST_SUITE(pool_tests, BasicTestingSetup)

//
// T-c1: pure math + record + DB. No tx surface yet.
//

BOOST_AUTO_TEST_CASE(pool_isqrt_product)
{
    // Exact squares and floors.
    BOOST_CHECK_EQUAL(PoolIsqrtProduct(4, 9), 6u);          // sqrt(36)
    BOOST_CHECK_EQUAL(PoolIsqrtProduct(2, 2), 2u);          // sqrt(4)
    BOOST_CHECK_EQUAL(PoolIsqrtProduct(2, 3), 2u);          // floor(sqrt(6)) = 2
    BOOST_CHECK_EQUAL(PoolIsqrtProduct(1, 1), 1u);
    BOOST_CHECK_EQUAL(PoolIsqrtProduct(1000000, 1000000), 1000000u);
    BOOST_CHECK_EQUAL(PoolIsqrtProduct(999999, 1000001), 999999u);   // floor((10^6)^2 - 1 root)

    // Zero / bounds.
    BOOST_CHECK_EQUAL(PoolIsqrtProduct(0, 5), 0u);
    BOOST_CHECK_EQUAL(PoolIsqrtProduct(5, 0), 0u);
    BOOST_CHECK_EQUAL(PoolIsqrtProduct(POOL_MAX_AMOUNT + 1, 1), 0u);
    BOOST_CHECK_EQUAL(PoolIsqrtProduct(1, POOL_MAX_AMOUNT + 1), 0u);

    // The largest legal product: root must fit comfortably (< 2^53).
    const uint64_t rootMax = PoolIsqrtProduct(POOL_MAX_AMOUNT, POOL_MAX_AMOUNT);
    BOOST_CHECK_EQUAL(rootMax, POOL_MAX_AMOUNT);
    // Floor property at the max boundary.
    const uint64_t r = PoolIsqrtProduct(POOL_MAX_AMOUNT, POOL_MAX_AMOUNT - 1);
    BOOST_CHECK((unsigned __int128)r * r <= (unsigned __int128)POOL_MAX_AMOUNT * (POOL_MAX_AMOUNT - 1));
    BOOST_CHECK((unsigned __int128)(r + 1) * (r + 1) > (unsigned __int128)POOL_MAX_AMOUNT * (POOL_MAX_AMOUNT - 1));
}

BOOST_AUTO_TEST_CASE(pool_lp_mint_initial)
{
    uint64_t toCreator = 0, supply0 = 0;

    // sqrt(2000*2000) = 2000 > MIN_LIQUIDITY(1000): creator gets 1000.
    BOOST_CHECK(PoolLpMintInitial(2000, 2000, toCreator, supply0));
    BOOST_CHECK_EQUAL(supply0, 2000u);
    BOOST_CHECK_EQUAL(toCreator, 1000u);

    // Boundary: sqrt = MIN_LIQUIDITY exactly -> creator would get 0 -> reject.
    BOOST_CHECK(!PoolLpMintInitial(1000, 1000, toCreator, supply0));
    // Just above: sqrt(1001*1002) = 1001 -> creator gets 1.
    BOOST_CHECK(PoolLpMintInitial(1001, 1002, toCreator, supply0));
    BOOST_CHECK_EQUAL(supply0, 1001u);
    BOOST_CHECK_EQUAL(toCreator, 1u);

    // Zero / negative / bounds.
    BOOST_CHECK(!PoolLpMintInitial(0, 5000, toCreator, supply0));
    BOOST_CHECK(!PoolLpMintInitial(5000, 0, toCreator, supply0));
    BOOST_CHECK(!PoolLpMintInitial(5000, -1, toCreator, supply0));
    BOOST_CHECK(!PoolLpMintInitial(POOL_MAX_AMOUNT + 1, 5000, toCreator, supply0));
}

BOOST_AUTO_TEST_CASE(pool_lp_mint_proportional)
{
    uint64_t minted = 0;

    // Balanced add: 10% of both sides -> 10% of supply.
    BOOST_CHECK(PoolLpMintProportional(100, 200, 1000, 2000, 5000, minted));
    BOOST_CHECK_EQUAL(minted, 500u);

    // Unbalanced add: the smaller ratio rules (the excess is donated).
    BOOST_CHECK(PoolLpMintProportional(100, 4000, 1000, 2000, 5000, minted));
    BOOST_CHECK_EQUAL(minted, 500u);   // note side: 10%; btx side would be 200%
    BOOST_CHECK(PoolLpMintProportional(1000, 200, 1000, 2000, 5000, minted));
    BOOST_CHECK_EQUAL(minted, 500u);   // btx side: 10%

    // Floor rounding: 1 unit into a large pool.
    BOOST_CHECK(!PoolLpMintProportional(1, 1, 1000000, 1000000, 5000, minted));  // mints 0 -> reject

    // Zero / empty-pool / bounds.
    BOOST_CHECK(!PoolLpMintProportional(0, 200, 1000, 2000, 5000, minted));
    BOOST_CHECK(!PoolLpMintProportional(100, 0, 1000, 2000, 5000, minted));
    BOOST_CHECK(!PoolLpMintProportional(100, 200, 0, 2000, 5000, minted));
    BOOST_CHECK(!PoolLpMintProportional(100, 200, 1000, 2000, 0, minted));
    BOOST_CHECK(!PoolLpMintProportional(POOL_MAX_AMOUNT, POOL_MAX_AMOUNT,
                                        POOL_MAX_AMOUNT, POOL_MAX_AMOUNT, POOL_MAX_AMOUNT, minted));
    // (post-add S and reserves would leave the envelope)
}

BOOST_AUTO_TEST_CASE(pool_lp_redeem)
{
    uint64_t noteOut = 0;
    CAmount btxOut = 0;

    // 10% burn takes 10% of each side.
    BOOST_CHECK(PoolLpRedeemAmounts(500, 1000, 2000, 5000, noteOut, btxOut));
    BOOST_CHECK_EQUAL(noteOut, 100u);
    BOOST_CHECK_EQUAL(btxOut, 200);

    // The MIN_LIQUIDITY floor is never redeemable.
    BOOST_CHECK(PoolLpRedeemAmounts(4000, 1000, 2000, 5000, noteOut, btxOut));   // leaves exactly 1000
    BOOST_CHECK(!PoolLpRedeemAmounts(4001, 1000, 2000, 5000, noteOut, btxOut));  // would leave 999
    BOOST_CHECK(!PoolLpRedeemAmounts(5000, 1000, 2000, 5000, noteOut, btxOut));  // full drain
    BOOST_CHECK(!PoolLpRedeemAmounts(5001, 1000, 2000, 5000, noteOut, btxOut));  // > supply

    // Zero-side companion: a side that floors to 0 is OMITTED (returned 0), not
    // rejected - only a burn paying NOTHING (both sides 0) is invalid.
    // Both sides floor to 0 (burn=1 into a huge, balanced supply): reject.
    BOOST_CHECK(!PoolLpRedeemAmounts(1, 1000, 2000, 5000000, noteOut, btxOut));
    // Note side floors to 0, BTX side positive: accept with noteOut == 0.
    noteOut = 7; btxOut = 7;
    BOOST_CHECK(PoolLpRedeemAmounts(1, 1000, 5000000, 5000000, noteOut, btxOut));
    BOOST_CHECK_EQUAL(noteOut, 0u);
    BOOST_CHECK_EQUAL(btxOut, 1);
    // BTX side floors to 0, note side positive: accept with btxOut == 0.
    noteOut = 7; btxOut = 7;
    BOOST_CHECK(PoolLpRedeemAmounts(1, 5000000, 1000, 5000000, noteOut, btxOut));
    BOOST_CHECK_EQUAL(noteOut, 1u);
    BOOST_CHECK_EQUAL(btxOut, 0);

    // Zero / bounds.
    BOOST_CHECK(!PoolLpRedeemAmounts(0, 1000, 2000, 5000, noteOut, btxOut));
    BOOST_CHECK(!PoolLpRedeemAmounts(500, 0, 2000, 5000, noteOut, btxOut));
    BOOST_CHECK(!PoolLpRedeemAmounts(500, 1000, 0, 5000, noteOut, btxOut));
}

BOOST_AUTO_TEST_CASE(pool_swap_out)
{
    uint64_t out = 0;

    // Known value, zero-fee impossible (fee bounds 1..100), use 30 bps:
    // in=1000 into X=100000/Y=100000: inFee = 1000*9970 = 9970000;
    // out = 9970000*100000 / (100000*10000 + 9970000) = 997000000000/1009970000 = 987.
    BOOST_CHECK(PoolSwapOut(1000, 100000, 100000, 30, out));
    BOOST_CHECK_EQUAL(out, 987u);

    // k never decreases: (X+in)(Y-out) >= X*Y across a magnitude sweep.
    const uint64_t vals[] = {1, 7, 999, 12345, 1000000, 123456789, 2100000000000000ULL};
    for (uint64_t X : vals) {
        for (uint64_t Y : vals) {
            for (uint64_t in : vals) {
                if (X < 2 || Y < 2)
                    continue;
                uint64_t o = 0;
                if (!PoolSwapOut(in, X, Y, 30, o))
                    continue;   // bounds/dust rejections are fine; only verify accepted swaps
                const unsigned __int128 kBefore = (unsigned __int128)X * Y;
                const unsigned __int128 kAfter = ((unsigned __int128)X + in) * (Y - o);
                BOOST_CHECK(kAfter >= kBefore);
                BOOST_CHECK(o < Y);
            }
        }
    }

    // Round-trip never profits: swap in, swap the proceeds back, get less.
    uint64_t fwd = 0, back = 0;
    BOOST_CHECK(PoolSwapOut(50000, 1000000, 3000000, 30, fwd));
    BOOST_CHECK(PoolSwapOut(fwd, 3000000 - fwd, 1000000 + 50000, 30, back));
    BOOST_CHECK(back < 50000u);

    // Drain protection: a huge swap cannot take the last unit of the out side.
    BOOST_CHECK(PoolSwapOut(POOL_MAX_AMOUNT / 2, 1000, 1000, 30, out));
    BOOST_CHECK(out < 1000u);

    // Fee bounds enforced.
    BOOST_CHECK(!PoolSwapOut(1000, 100000, 100000, 0, out));
    BOOST_CHECK(!PoolSwapOut(1000, 100000, 100000, 101, out));

    // Zero / magnitude bounds.
    BOOST_CHECK(!PoolSwapOut(0, 100000, 100000, 30, out));
    BOOST_CHECK(!PoolSwapOut(1000, 0, 100000, 30, out));
    BOOST_CHECK(!PoolSwapOut(1000, 100000, 0, 30, out));
    BOOST_CHECK(!PoolSwapOut(POOL_MAX_AMOUNT + 1, 100000, 100000, 30, out));
    BOOST_CHECK(!PoolSwapOut(POOL_MAX_AMOUNT, POOL_MAX_AMOUNT, 100000, 30, out));  // post-swap in-side leaves envelope

    // Dust in a lopsided pool: out floors to 0 -> reject.
    BOOST_CHECK(!PoolSwapOut(1, POOL_MAX_AMOUNT / 2, 10, 30, out));
}

BOOST_AUTO_TEST_CASE(pool_escrow_script)
{
    const CScript script1 = PoolEscrowScript(1);
    const CScript script2 = PoolEscrowScript(2);

    BOOST_CHECK(IsPoolEscrowScript(script1));
    BOOST_CHECK(IsPoolEscrowScript(script2));
    BOOST_CHECK(script1 != script2);

    // Deterministic.
    BOOST_CHECK(PoolEscrowScript(1) == script1);
    BOOST_CHECK(PoolEscrowTag(1) == PoolEscrowTag(1));
    BOOST_CHECK(PoolEscrowTag(1) != PoolEscrowTag(2));

    BOOST_CHECK(!IsPoolEscrowScript(CScript() << OP_TRUE));
}

BOOST_AUTO_TEST_CASE(pool_record_serialization)
{
    CPool pool;
    pool.nPoolID = 7;
    pool.nFeeBps = 30;
    pool.nNoteReserve = 123456789;
    pool.amountBtxReserve = 987654321;
    pool.nLpSupply = 111111;
    pool.outNote = COutPoint(uint256S("0xabc0000000000000000000000000000000000000000000000000000000000000"), 0);
    pool.outBtx = COutPoint(uint256S("0xabc0000000000000000000000000000000000000000000000000000000000000"), 1);
    pool.nCreateHeight = 42;

    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << pool;

    CPool pool2;
    ss >> pool2;

    BOOST_CHECK_EQUAL(pool2.nPoolID, pool.nPoolID);
    BOOST_CHECK_EQUAL(pool2.nFeeBps, pool.nFeeBps);
    BOOST_CHECK_EQUAL(pool2.nNoteReserve, pool.nNoteReserve);
    BOOST_CHECK_EQUAL(pool2.amountBtxReserve, pool.amountBtxReserve);
    BOOST_CHECK_EQUAL(pool2.nLpSupply, pool.nLpSupply);
    BOOST_CHECK(pool2.outNote == pool.outNote);
    BOOST_CHECK(pool2.outBtx == pool.outBtx);
    BOOST_CHECK_EQUAL(pool2.nCreateHeight, pool.nCreateHeight);

    // Unknown future version rejects (forward-compat guard).
    CDataStream ssBad(SER_DISK, PROTOCOL_VERSION);
    ssBad << (uint8_t)(POOL_SER_VERSION + 1);
    BOOST_CHECK_THROW(ssBad >> pool2, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(pool_db_roundtrip)
{
    PoolDB db(1 << 20, true, true);   // in-memory

    CPool pool;
    pool.nPoolID = 3;
    pool.nFeeBps = 30;
    pool.nNoteReserve = 5000;
    pool.amountBtxReserve = 9000;
    pool.nLpSupply = 6000;
    pool.nCreateHeight = 10;

    BOOST_CHECK(!db.HavePool(3));

    // Atomic block-effects write: pool + marker land together.
    const uint256 hashBlock = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    BOOST_CHECK(db.WriteBlockEffects({pool}, {}, hashBlock));

    BOOST_CHECK(db.HavePool(3));
    CPool pool2;
    BOOST_CHECK(db.GetPool(3, pool2));
    BOOST_CHECK_EQUAL(pool2.nNoteReserve, 5000u);
    BOOST_CHECK_EQUAL(pool2.nLpSupply, 6000u);

    uint256 hashBest;
    BOOST_CHECK(db.GetBestBlock(hashBest));
    BOOST_CHECK(hashBest == hashBlock);

    BOOST_CHECK_EQUAL(db.GetPools().size(), 1u);

    // Disconnect path: removal + marker in one atomic batch.
    const uint256 hashPrev = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");
    BOOST_CHECK(db.WriteBlockEffects({}, {3}, hashPrev));
    BOOST_CHECK(!db.HavePool(3));
    BOOST_CHECK(db.GetBestBlock(hashBest));
    BOOST_CHECK(hashBest == hashPrev);
    BOOST_CHECK_EQUAL(db.GetPools().size(), 0u);
}

//
// T-c2: tx v15 scaffolding - payload round-trips + context-free shape checks.
//

static std::vector<unsigned char> PoolFreshPubKey()
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pub = key.GetPubKey();
    return std::vector<unsigned char>(pub.begin(), pub.end());
}

template <typename T>
static std::vector<unsigned char> EncodePoolPayload(const T& payload)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

static std::vector<unsigned char> DummySig(size_t n = 71)
{
    return std::vector<unsigned char>(n, 0x30);
}

static void AddDummyInputs(CMutableTransaction& mtx, size_t n)
{
    for (size_t i = 0; i < n; i++)
        mtx.vin.emplace_back(COutPoint(uint256S(strprintf("0x%064x", i + 1)), i));
}

static std::string PoolShapeReject(const CMutableTransaction& mtx)
{
    CValidationState state;
    if (CheckPoolTransactionShape(CTransaction(mtx), state))
        return "OK";
    return state.GetRejectReason();
}

/** A shape-valid CREATE for pool 7: seed 4000 units / 4000 sats (S0 = 4000). */
static CMutableTransaction ValidCreateTx(PoolCreate& create)
{
    create.nPoolID = 7;
    create.nFeeBps = POOL_FEE_BPS_DEFAULT;
    create.nInitNoteUnits = 4000;
    create.amountInitBtx = 4000;
    create.nNoteChangeUnits = 0;
    create.vchCreatorPubKey = PoolFreshPubKey();
    create.vchCreatorSig = DummySig();
    create.vApproverIndex = {0};
    create.vApproverSig = {DummySig()};

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_POOL_VERSION;
    mtx.nPoolOp = POOL_OP_CREATE;
    AddDummyInputs(mtx, 2);
    mtx.vout.emplace_back(POOL_DUST_VALUE, PoolEscrowScript(7));
    mtx.vout.emplace_back(4000, PoolEscrowScript(7));
    mtx.vout.emplace_back(POOL_DUST_VALUE, PoolScriptForPubKey(create.vchCreatorPubKey));
    mtx.vchPoolPayload = EncodePoolPayload(create);
    return mtx;
}

BOOST_AUTO_TEST_CASE(pool_payload_roundtrip)
{
    PoolSwap swap;
    swap.nPoolID = 9;
    swap.nPriorNoteReserve = 111;
    swap.amountPriorBtxReserve = 222;
    swap.nPriorLpSupply = 333;
    swap.nDirection = POOL_SWAP_NOTE_TO_BTX;
    swap.nAmountIn = 444;
    swap.nMinOut = 555;
    swap.nAmountOut = 666;
    swap.nNoteChangeUnits = 777;
    swap.vchTraderPubKey = PoolFreshPubKey();
    swap.vchTraderSig = DummySig();

    PoolSwap swap2;
    BOOST_CHECK(DecodePoolPayload(EncodePoolPayload(swap), swap2));
    BOOST_CHECK_EQUAL(swap2.nPoolID, swap.nPoolID);
    BOOST_CHECK_EQUAL(swap2.nPriorNoteReserve, swap.nPriorNoteReserve);
    BOOST_CHECK_EQUAL(swap2.amountPriorBtxReserve, swap.amountPriorBtxReserve);
    BOOST_CHECK_EQUAL(swap2.nPriorLpSupply, swap.nPriorLpSupply);
    BOOST_CHECK_EQUAL(swap2.nDirection, swap.nDirection);
    BOOST_CHECK_EQUAL(swap2.nAmountIn, swap.nAmountIn);
    BOOST_CHECK_EQUAL(swap2.nMinOut, swap.nMinOut);
    BOOST_CHECK_EQUAL(swap2.nAmountOut, swap.nAmountOut);
    BOOST_CHECK_EQUAL(swap2.nNoteChangeUnits, swap.nNoteChangeUnits);
    BOOST_CHECK(swap2.vchTraderPubKey == swap.vchTraderPubKey);

    // Trailing bytes reject.
    std::vector<unsigned char> vch = EncodePoolPayload(swap);
    vch.push_back(0x00);
    BOOST_CHECK(!DecodePoolPayload(vch, swap2));

    // The other three structs: encode/decode identity on a field spot-check.
    PoolCreate create, create2;
    create.nPoolID = 3;
    create.nFeeBps = 30;
    create.nInitNoteUnits = 5000;
    create.amountInitBtx = 6000;
    create.vchCreatorPubKey = PoolFreshPubKey();
    create.vchCreatorSig = DummySig();
    create.vApproverIndex = {0, 2};
    create.vApproverSig = {DummySig(), DummySig(70)};
    BOOST_CHECK(DecodePoolPayload(EncodePoolPayload(create), create2));
    BOOST_CHECK_EQUAL(create2.nInitNoteUnits, 5000u);
    BOOST_CHECK_EQUAL(create2.vApproverIndex.size(), 2u);

    PoolAddLiq add, add2;
    add.nPoolID = 3;
    add.nPriorNoteReserve = 1000;
    add.amountPriorBtxReserve = 2000;
    add.nPriorLpSupply = 1414;
    add.nAddNoteUnits = 100;
    add.amountAddBtx = 200;
    add.nLpMinted = 141;
    add.vchProviderPubKey = PoolFreshPubKey();
    add.vchProviderSig = DummySig();
    BOOST_CHECK(DecodePoolPayload(EncodePoolPayload(add), add2));
    BOOST_CHECK_EQUAL(add2.nLpMinted, 141u);

    PoolRemoveLiq rem, rem2;
    rem.nPoolID = 3;
    rem.nPriorNoteReserve = 1000;
    rem.amountPriorBtxReserve = 2000;
    rem.nPriorLpSupply = 1414;
    rem.nBurnLp = 100;
    rem.nNoteOut = 70;
    rem.amountBtxOut = 141;
    rem.vchProviderPubKey = PoolFreshPubKey();
    rem.vchProviderSig = DummySig();
    BOOST_CHECK(DecodePoolPayload(EncodePoolPayload(rem), rem2));
    BOOST_CHECK_EQUAL(rem2.amountBtxOut, 141);

    // RETIRE - single-partner (insolvency) path.
    PoolRetire ret, ret2;
    ret.nPoolID = 3;
    ret.nPriorNoteReserve = 1000;
    ret.amountPriorBtxReserve = 2000;
    ret.nPriorLpSupply = POOL_MIN_LIQUIDITY;
    ret.nFeeBps = 30;
    ret.nCreateHeight = 12345;
    ret.nTriggerPartnerIndex = 2;
    ret.vchTriggerSig = DummySig();
    BOOST_CHECK(DecodePoolPayload(EncodePoolPayload(ret), ret2));
    BOOST_CHECK_EQUAL(ret2.nPoolID, 3u);
    BOOST_CHECK_EQUAL(ret2.nFeeBps, 30u);
    BOOST_CHECK_EQUAL(ret2.nCreateHeight, 12345);
    BOOST_CHECK_EQUAL(ret2.nTriggerPartnerIndex, 2u);
    BOOST_CHECK(ret2.vchTriggerSig == ret.vchTriggerSig);
    BOOST_CHECK(ret2.vApproverIndex.empty());

    // RETIRE - M-of-N path.
    PoolRetire retM, retM2;
    retM.nPoolID = 3;
    retM.nPriorLpSupply = POOL_MIN_LIQUIDITY;
    retM.vApproverIndex = {0, 3};
    retM.vApproverSig = {DummySig(), DummySig(70)};
    BOOST_CHECK(DecodePoolPayload(EncodePoolPayload(retM), retM2));
    BOOST_CHECK_EQUAL(retM2.vApproverIndex.size(), 2u);
    BOOST_CHECK(retM2.vchTriggerSig.empty());
}

BOOST_AUTO_TEST_CASE(pool_tx_serialization)
{
    PoolCreate create;
    CMutableTransaction mtx = ValidCreateTx(create);

    // v15 trailer survives tx ser/deser.
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << mtx;
    CMutableTransaction mtx2(deserialize, ss);
    BOOST_CHECK_EQUAL(mtx2.nVersion, TRANSACTION_POOL_VERSION);
    BOOST_CHECK_EQUAL(mtx2.nPoolOp, POOL_OP_CREATE);
    BOOST_CHECK(mtx2.vchPoolPayload == mtx.vchPoolPayload);
    BOOST_CHECK(CTransaction(mtx2).GetHash() == CTransaction(mtx).GetHash());

    // The payload is INSIDE the txid commitment.
    CMutableTransaction mtxMut = mtx;
    mtxMut.vchPoolPayload.back() ^= 0x01;
    BOOST_CHECK(CTransaction(mtxMut).GetHash() != CTransaction(mtx).GetHash());
    mtxMut = mtx;
    mtxMut.nPoolOp = POOL_OP_SWAP;
    BOOST_CHECK(CTransaction(mtxMut).GetHash() != CTransaction(mtx).GetHash());
}

BOOST_AUTO_TEST_CASE(pool_sighash_domains)
{
    const uint256 hp = uint256S("0x01");
    const uint256 ho = uint256S("0x02");

    PoolAddLiq add;
    add.nPoolID = 1;
    PoolRemoveLiq rem;
    rem.nPoolID = 1;
    PoolSwap swap;
    swap.nPoolID = 1;

    // Domain separation: identical fields, four distinct hashes.
    const uint256 h1 = PoolCreateSigHash(1, 30, 0, 0, 0, hp, ho);
    const uint256 h2 = PoolAddLiqSigHash(add, hp, ho);
    const uint256 h3 = PoolRemoveLiqSigHash(rem, hp, ho);
    const uint256 h4 = PoolSwapSigHash(swap, hp, ho);
    BOOST_CHECK(h1 != h2 && h1 != h3 && h1 != h4 && h2 != h3 && h2 != h4 && h3 != h4);

    // Prior-binding: any prior field change moves the swap sighash.
    PoolSwap swapMut = swap;
    swapMut.nPriorNoteReserve = 1;
    BOOST_CHECK(PoolSwapSigHash(swapMut, hp, ho) != h4);
    swapMut = swap;
    swapMut.nMinOut = 1;
    BOOST_CHECK(PoolSwapSigHash(swapMut, hp, ho) != h4);
    BOOST_CHECK(PoolSwapSigHash(swap, uint256S("0x03"), ho) != h4);
    BOOST_CHECK(PoolSwapSigHash(swap, hp, uint256S("0x03")) != h4);

    // RETIRE is a fifth distinct domain, and binds every payload field.
    PoolRetire ret;
    ret.nPoolID = 1;
    const uint256 h5 = PoolRetireSigHash(ret, hp, ho);
    BOOST_CHECK(h5 != h1 && h5 != h2 && h5 != h3 && h5 != h4);
    PoolRetire retMut = ret;
    retMut.nPriorNoteReserve = 1;
    BOOST_CHECK(PoolRetireSigHash(retMut, hp, ho) != h5);
    retMut = ret;
    retMut.nTriggerPartnerIndex = 1;
    BOOST_CHECK(PoolRetireSigHash(retMut, hp, ho) != h5);
    retMut = ret;
    retMut.nCreateHeight = 1;
    BOOST_CHECK(PoolRetireSigHash(retMut, hp, ho) != h5);
    BOOST_CHECK(PoolRetireSigHash(ret, uint256S("0x03"), ho) != h5);
    BOOST_CHECK(PoolRetireSigHash(ret, hp, uint256S("0x03")) != h5);
}

BOOST_AUTO_TEST_CASE(pool_shape_create)
{
    PoolCreate create;
    CMutableTransaction mtx = ValidCreateTx(create);
    BOOST_CHECK_EQUAL(PoolShapeReject(mtx), "OK");

    // Op range.
    CMutableTransaction bad = mtx;
    bad.nPoolOp = 0;
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-op");
    bad.nPoolOp = 6;   // POOL_OP_RETIRE(5) is now valid; 6 is the first out-of-range op
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-op");

    // Fee bounds.
    PoolCreate c2 = create;
    c2.nFeeBps = POOL_FEE_BPS_MAX + 1;
    bad = mtx;
    bad.vchPoolPayload = EncodePoolPayload(c2);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-create-fee");

    // Seed below the MIN_LIQUIDITY floor.
    c2 = create;
    c2.nInitNoteUnits = 1000;
    c2.amountInitBtx = 1000;
    bad = mtx;
    bad.vchPoolPayload = EncodePoolPayload(c2);
    bad.vout[1].nValue = 1000;
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-create-seed");

    // Escrow pair: wrong script at vout[0] / wrong value at vout[1].
    bad = mtx;
    bad.vout[0].scriptPubKey = PoolEscrowScript(8);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-note-escrow-output");
    bad = mtx;
    bad.vout[1].nValue = 3999;
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-btx-escrow-output");

    // LP output must pay the declared creator key at dust.
    bad = mtx;
    bad.vout[2] = CTxOut(POOL_DUST_VALUE, PoolScriptForPubKey(PoolFreshPubKey()));
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-lp-output");

    // Declared note change without the output.
    c2 = create;
    c2.nNoteChangeUnits = 50;
    bad = mtx;
    bad.vchPoolPayload = EncodePoolPayload(c2);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-note-change-output");

    // Approvers: unsorted rejected.
    c2 = create;
    c2.vApproverIndex = {1, 1};
    c2.vApproverSig = {DummySig(), DummySig()};
    bad = mtx;
    bad.vchPoolPayload = EncodePoolPayload(c2);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-create-approvers");

    // Garbage payload.
    bad = mtx;
    bad.vchPoolPayload = {0x01, 0x02};
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-create-payload");
}

BOOST_AUTO_TEST_CASE(pool_shape_add_remove)
{
    // ADD_LIQ: the min-rule formula is enforced context-free.
    PoolAddLiq add;
    add.nPoolID = 7;
    add.nPriorNoteReserve = 1000;
    add.amountPriorBtxReserve = 2000;
    add.nPriorLpSupply = 5000;
    add.nAddNoteUnits = 100;
    add.amountAddBtx = 200;
    add.nLpMinted = 500;
    add.nNoteChangeUnits = 0;
    add.vchProviderPubKey = PoolFreshPubKey();
    add.vchProviderSig = DummySig();

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_POOL_VERSION;
    mtx.nPoolOp = POOL_OP_ADD_LIQ;
    AddDummyInputs(mtx, 3);
    mtx.vout.emplace_back(POOL_DUST_VALUE, PoolEscrowScript(7));
    mtx.vout.emplace_back(2200, PoolEscrowScript(7));
    mtx.vout.emplace_back(POOL_DUST_VALUE, PoolScriptForPubKey(add.vchProviderPubKey));
    mtx.vchPoolPayload = EncodePoolPayload(add);
    BOOST_CHECK_EQUAL(PoolShapeReject(mtx), "OK");

    PoolAddLiq a2 = add;
    a2.nLpMinted = 501;   // formula says 500
    CMutableTransaction bad = mtx;
    bad.vchPoolPayload = EncodePoolPayload(a2);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-add-amounts");

    // Escrow input pair is mandatory: fewer than 3 inputs cannot carry it + funding.
    bad = mtx;
    bad.vin.resize(2);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-vin-size");

    // REMOVE_LIQ: payouts enforced against the redeem formula.
    PoolRemoveLiq rem;
    rem.nPoolID = 7;
    rem.nPriorNoteReserve = 1000;
    rem.amountPriorBtxReserve = 2000;
    rem.nPriorLpSupply = 5000;
    rem.nBurnLp = 500;
    rem.nNoteOut = 100;
    rem.amountBtxOut = 200;
    rem.nLpChangeUnits = 0;
    rem.vchProviderPubKey = PoolFreshPubKey();
    rem.vchProviderSig = DummySig();

    CMutableTransaction mtxR;
    mtxR.nVersion = TRANSACTION_POOL_VERSION;
    mtxR.nPoolOp = POOL_OP_REMOVE_LIQ;
    AddDummyInputs(mtxR, 3);
    mtxR.vout.emplace_back(POOL_DUST_VALUE, PoolEscrowScript(7));
    mtxR.vout.emplace_back(1800, PoolEscrowScript(7));
    mtxR.vout.emplace_back(POOL_DUST_VALUE, PoolScriptForPubKey(rem.vchProviderPubKey));
    mtxR.vout.emplace_back(200, PoolScriptForPubKey(rem.vchProviderPubKey));
    mtxR.vchPoolPayload = EncodePoolPayload(rem);
    BOOST_CHECK_EQUAL(PoolShapeReject(mtxR), "OK");

    PoolRemoveLiq r2 = rem;
    r2.nNoteOut = 101;   // formula says 100
    bad = mtxR;
    bad.vchPoolPayload = EncodePoolPayload(r2);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-remove-amounts");

    // BTX payout must equal the formula amount to the declared key.
    bad = mtxR;
    bad.vout[3].nValue = 199;
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-btx-payout");
}

BOOST_AUTO_TEST_CASE(pool_shape_remove_zero_side)
{
    // Zero-side companion: a REMOVE whose note side floors to 0 OMITS the note
    // payout, so the BTX payout packs up to vout[2].
    PoolRemoveLiq rem;
    rem.nPoolID = 7;
    rem.nPriorNoteReserve = 1000;
    rem.amountPriorBtxReserve = 5000000;
    rem.nPriorLpSupply = 5000000;
    rem.nBurnLp = 1000;
    rem.nNoteOut = 0;          // floor(1000*1000/5000000) = 0 -> omitted
    rem.amountBtxOut = 1000;   // floor(1000*5000000/5000000) = 1000
    rem.nLpChangeUnits = 0;
    rem.vchProviderPubKey = PoolFreshPubKey();
    rem.vchProviderSig = DummySig();

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_POOL_VERSION;
    mtx.nPoolOp = POOL_OP_REMOVE_LIQ;
    AddDummyInputs(mtx, 3);
    mtx.vout.emplace_back(POOL_DUST_VALUE, PoolEscrowScript(7));               // vout[0] note escrow
    mtx.vout.emplace_back(5000000 - 1000, PoolEscrowScript(7));               // vout[1] BTX escrow (Y - btxOut)
    mtx.vout.emplace_back(1000, PoolScriptForPubKey(rem.vchProviderPubKey));  // vout[2] BTX payout (note omitted)
    mtx.vchPoolPayload = EncodePoolPayload(rem);
    BOOST_CHECK_EQUAL(PoolShapeReject(mtx), "OK");

    // The BTX payout now lives at vout[2]: mis-valuing it is caught there.
    CMutableTransaction bad = mtx;
    bad.vout[2].nValue = 999;
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-btx-payout");

    // Symmetric: BTX side floors to 0, note payout present at vout[2].
    PoolRemoveLiq rem2;
    rem2.nPoolID = 7;
    rem2.nPriorNoteReserve = 5000000;
    rem2.amountPriorBtxReserve = 1000;
    rem2.nPriorLpSupply = 5000000;
    rem2.nBurnLp = 1000;
    rem2.nNoteOut = 1000;      // floor(1000*5000000/5000000) = 1000
    rem2.amountBtxOut = 0;     // floor(1000*1000/5000000) = 0 -> omitted
    rem2.nLpChangeUnits = 0;
    rem2.vchProviderPubKey = PoolFreshPubKey();
    rem2.vchProviderSig = DummySig();

    CMutableTransaction mtx2;
    mtx2.nVersion = TRANSACTION_POOL_VERSION;
    mtx2.nPoolOp = POOL_OP_REMOVE_LIQ;
    AddDummyInputs(mtx2, 3);
    mtx2.vout.emplace_back(POOL_DUST_VALUE, PoolEscrowScript(7));                          // vout[0] note escrow
    mtx2.vout.emplace_back(1000, PoolEscrowScript(7));                                     // vout[1] BTX escrow (Y - 0)
    mtx2.vout.emplace_back(POOL_DUST_VALUE, PoolScriptForPubKey(rem2.vchProviderPubKey));  // vout[2] note payout (BTX omitted)
    mtx2.vchPoolPayload = EncodePoolPayload(rem2);
    BOOST_CHECK_EQUAL(PoolShapeReject(mtx2), "OK");

    // Both-zero payout is impossible (redeem rejects it): the formula guard fires.
    PoolRemoveLiq remBoth = rem;
    remBoth.nBurnLp = 1;
    remBoth.nPriorNoteReserve = 1000;
    remBoth.amountPriorBtxReserve = 2000;
    remBoth.nPriorLpSupply = 5000000;
    remBoth.nNoteOut = 0;
    remBoth.amountBtxOut = 0;
    CMutableTransaction badBoth = mtx;
    badBoth.vchPoolPayload = EncodePoolPayload(remBoth);
    BOOST_CHECK_EQUAL(PoolShapeReject(badBoth), "bad-pool-remove-amounts");
}

BOOST_AUTO_TEST_CASE(pool_shape_retire)
{
    // Valid M-of-N RETIRE at the locked floor: spends the custody pair, force-
    // pays the floor BTX (>= Y) to a P2PKH at vout[0], no escrow-shaped output.
    PoolRetire ret;
    ret.nPoolID = 7;
    ret.nPriorNoteReserve = 1000;
    ret.amountPriorBtxReserve = 2000;
    ret.nPriorLpSupply = POOL_MIN_LIQUIDITY;
    ret.nFeeBps = POOL_FEE_BPS_DEFAULT;
    ret.nCreateHeight = 5;
    ret.nTriggerPartnerIndex = 0;
    ret.vApproverIndex = {0};
    ret.vApproverSig = {DummySig()};

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_POOL_VERSION;
    mtx.nPoolOp = POOL_OP_RETIRE;
    AddDummyInputs(mtx, 2);
    mtx.vout.emplace_back(2000, PoolScriptForPubKey(PoolFreshPubKey()));   // vout[0] floor-BTX payout, P2PKH, == Y
    mtx.vchPoolPayload = EncodePoolPayload(ret);
    BOOST_CHECK_EQUAL(PoolShapeReject(mtx), "OK");

    // A larger payout (dust + fee sweep) is fine: value >= Y.
    CMutableTransaction okBig = mtx;
    okBig.vout[0].nValue = 3000;
    BOOST_CHECK_EQUAL(PoolShapeReject(okBig), "OK");

    // Not at the floor.
    PoolRetire r = ret;
    r.nPriorLpSupply = POOL_MIN_LIQUIDITY + 1;
    CMutableTransaction bad = mtx;
    bad.vchPoolPayload = EncodePoolPayload(r);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-retire-not-floor");

    // Zero reserve.
    r = ret;
    r.nPriorNoteReserve = 0;
    bad = mtx;
    bad.vchPoolPayload = EncodePoolPayload(r);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-retire-amounts");

    // Fee out of range.
    r = ret;
    r.nFeeBps = POOL_FEE_BPS_MAX + 1;
    bad = mtx;
    bad.vchPoolPayload = EncodePoolPayload(r);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-retire-fee");

    // Both auth paths populated.
    r = ret;
    r.vchTriggerSig = DummySig();   // keeps the M-of-N arrays too
    bad = mtx;
    bad.vchPoolPayload = EncodePoolPayload(r);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-retire-auth-shape");

    // Neither auth path populated.
    r = ret;
    r.vApproverIndex.clear();
    r.vApproverSig.clear();
    bad = mtx;
    bad.vchPoolPayload = EncodePoolPayload(r);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-retire-auth-shape");

    // M-of-N path must pin nTriggerPartnerIndex to 0.
    r = ret;
    r.nTriggerPartnerIndex = 1;
    bad = mtx;
    bad.vchPoolPayload = EncodePoolPayload(r);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-retire-auth-shape");

    // Approvers unsorted.
    r = ret;
    r.vApproverIndex = {1, 1};
    r.vApproverSig = {DummySig(), DummySig()};
    bad = mtx;
    bad.vchPoolPayload = EncodePoolPayload(r);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-retire-approvers");

    // Floor-BTX payout below Y.
    bad = mtx;
    bad.vout[0].nValue = 1999;
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-retire-payout");

    // Floor-BTX payout not a P2PKH shape.
    bad = mtx;
    bad.vout[0] = CTxOut(2000, PoolEscrowScript(7));
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-retire-payout");

    // A stray escrow-shaped output (would enter the UTXO set untagged).
    bad = mtx;
    bad.vout.emplace_back(POOL_DUST_VALUE, PoolEscrowScript(7));
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-retire-stray-escrow");

    // Fewer than the two custody inputs.
    bad = mtx;
    bad.vin.resize(1);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-vin-size");

    // Garbage payload.
    bad = mtx;
    bad.vchPoolPayload = {0x01, 0x02};
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-retire-payload");

    // Single-partner (insolvency) path is valid shape too.
    PoolRetire rs = ret;
    rs.vApproverIndex.clear();
    rs.vApproverSig.clear();
    rs.nTriggerPartnerIndex = 2;
    rs.vchTriggerSig = DummySig();
    CMutableTransaction mtxS = mtx;
    mtxS.vchPoolPayload = EncodePoolPayload(rs);
    BOOST_CHECK_EQUAL(PoolShapeReject(mtxS), "OK");

    // Single-partner path with a stray approver signature.
    PoolRetire rs2 = rs;
    rs2.vApproverSig = {DummySig()};
    CMutableTransaction badS = mtx;
    badS.vchPoolPayload = EncodePoolPayload(rs2);
    BOOST_CHECK_EQUAL(PoolShapeReject(badS), "bad-pool-retire-auth-shape");
}

BOOST_AUTO_TEST_CASE(pool_shape_swap)
{
    PoolSwap swap;
    swap.nPoolID = 7;
    swap.nPriorNoteReserve = 100000;
    swap.amountPriorBtxReserve = 100000;
    swap.nPriorLpSupply = 100000;
    swap.nDirection = POOL_SWAP_NOTE_TO_BTX;
    swap.nAmountIn = 1000;
    swap.nMinOut = 900;
    swap.nAmountOut = 987;   // formula value at 30bps (checked contextually, not here)
    swap.nNoteChangeUnits = 0;
    swap.vchTraderPubKey = PoolFreshPubKey();
    swap.vchTraderSig = DummySig();

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_POOL_VERSION;
    mtx.nPoolOp = POOL_OP_SWAP;
    AddDummyInputs(mtx, 3);
    mtx.vout.emplace_back(POOL_DUST_VALUE, PoolEscrowScript(7));
    mtx.vout.emplace_back(100000 - 987, PoolEscrowScript(7));
    mtx.vout.emplace_back(987, PoolScriptForPubKey(swap.vchTraderPubKey));
    mtx.vchPoolPayload = EncodePoolPayload(swap);
    BOOST_CHECK_EQUAL(PoolShapeReject(mtx), "OK");

    // The min-out slippage guard is consensus shape.
    PoolSwap s2 = swap;
    s2.nMinOut = 988;
    CMutableTransaction bad = mtx;
    bad.vchPoolPayload = EncodePoolPayload(s2);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-swap-min-out");

    // Direction range.
    s2 = swap;
    s2.nDirection = 3;
    bad = mtx;
    bad.vchPoolPayload = EncodePoolPayload(s2);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-swap-direction");

    // Drain: out >= Y.
    s2 = swap;
    s2.nAmountOut = 100000;
    bad = mtx;
    bad.vchPoolPayload = EncodePoolPayload(s2);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-swap-amounts");

    // Payout must be the exact out amount.
    bad = mtx;
    bad.vout[2].nValue = 986;
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-btx-payout");

    // Direction 2: a note-change declaration is malformed (no trader note inputs).
    s2 = swap;
    s2.nDirection = POOL_SWAP_BTX_TO_NOTE;
    s2.nNoteChangeUnits = 5;
    bad = mtx;
    bad.vchPoolPayload = EncodePoolPayload(s2);
    BOOST_CHECK_EQUAL(PoolShapeReject(bad), "bad-pool-swap-change");

    // Direction 2 happy shape: note payout at vout[2], escrow grows by in.
    s2 = swap;
    s2.nDirection = POOL_SWAP_BTX_TO_NOTE;
    s2.nNoteChangeUnits = 0;
    CMutableTransaction mtx2;
    mtx2.nVersion = TRANSACTION_POOL_VERSION;
    mtx2.nPoolOp = POOL_OP_SWAP;
    AddDummyInputs(mtx2, 3);
    mtx2.vout.emplace_back(POOL_DUST_VALUE, PoolEscrowScript(7));
    mtx2.vout.emplace_back(100000 + 1000, PoolEscrowScript(7));
    mtx2.vout.emplace_back(POOL_DUST_VALUE, PoolScriptForPubKey(s2.vchTraderPubKey));
    mtx2.vchPoolPayload = EncodePoolPayload(s2);
    BOOST_CHECK_EQUAL(PoolShapeReject(mtx2), "OK");
}

//
// T-c3: coin tagging + spend guards.
//

BOOST_AUTO_TEST_CASE(pool_coin_tagging)
{
    // CREATE with note change: all four tagged positions via AddCoins.
    PoolCreate create;
    CMutableTransaction mtx = ValidCreateTx(create);
    create.nInitNoteUnits = 4000;
    create.nNoteChangeUnits = 250;
    mtx.vout.emplace_back(POOL_DUST_VALUE, PoolScriptForPubKey(create.vchCreatorPubKey));  // vout[3] note change
    mtx.vchPoolPayload = EncodePoolPayload(create);
    BOOST_CHECK_EQUAL(PoolShapeReject(mtx), "OK");

    CTransaction tx(mtx);
    CCoinsView base;
    CCoinsViewCache cache(&base);
    AddCoins(cache, tx, 100, 0, 0, 0, 0, 0, 0);

    const Coin& c0 = cache.AccessCoin(COutPoint(tx.GetHash(), 0));
    BOOST_CHECK(c0.fNote && c0.fPoolEscrow);                 // dual-tagged custody
    BOOST_CHECK_EQUAL(c0.nHouseID, 7);
    BOOST_CHECK_EQUAL(c0.nNoteUnits, 4000u);
    BOOST_CHECK_EQUAL(c0.nDemandHeight, 0u);

    const Coin& c1 = cache.AccessCoin(COutPoint(tx.GetHash(), 1));
    BOOST_CHECK(c1.fPoolEscrow && !c1.fNote && !c1.fLpShare);
    BOOST_CHECK_EQUAL(c1.nHouseID, 7);
    BOOST_CHECK_EQUAL(c1.out.nValue, 4000);

    const Coin& c2 = cache.AccessCoin(COutPoint(tx.GetHash(), 2));
    BOOST_CHECK(c2.fLpShare && !c2.fNote && !c2.fPoolEscrow);
    BOOST_CHECK_EQUAL(c2.nLpUnits, 4000u - POOL_MIN_LIQUIDITY);   // isqrt(4000*4000) - lock

    const Coin& c3 = cache.AccessCoin(COutPoint(tx.GetHash(), 3));
    BOOST_CHECK(c3.fNote && !c3.fPoolEscrow);
    BOOST_CHECK_EQUAL(c3.nNoteUnits, 250u);

    // SWAP dir 2: note payout tagged, escrow updated from payload alone.
    PoolSwap swap;
    swap.nPoolID = 7;
    swap.nPriorNoteReserve = 100000;
    swap.amountPriorBtxReserve = 100000;
    swap.nPriorLpSupply = 100000;
    swap.nDirection = POOL_SWAP_BTX_TO_NOTE;
    swap.nAmountIn = 1000;
    swap.nMinOut = 1;
    swap.nAmountOut = 987;
    swap.vchTraderPubKey = PoolFreshPubKey();
    swap.vchTraderSig = DummySig();
    CMutableTransaction mtxS;
    mtxS.nVersion = TRANSACTION_POOL_VERSION;
    mtxS.nPoolOp = POOL_OP_SWAP;
    AddDummyInputs(mtxS, 3);
    mtxS.vout.emplace_back(POOL_DUST_VALUE, PoolEscrowScript(7));
    mtxS.vout.emplace_back(101000, PoolEscrowScript(7));
    mtxS.vout.emplace_back(POOL_DUST_VALUE, PoolScriptForPubKey(swap.vchTraderPubKey));
    mtxS.vchPoolPayload = EncodePoolPayload(swap);
    BOOST_CHECK_EQUAL(PoolShapeReject(mtxS), "OK");

    CTransaction txS(mtxS);
    AddCoins(cache, txS, 101, 0, 0, 0, 0, 0, 0);
    const Coin& s0 = cache.AccessCoin(COutPoint(txS.GetHash(), 0));
    BOOST_CHECK(s0.fNote && s0.fPoolEscrow);
    BOOST_CHECK_EQUAL(s0.nNoteUnits, 100000u - 987u);
    const Coin& s2 = cache.AccessCoin(COutPoint(txS.GetHash(), 2));
    BOOST_CHECK(s2.fNote && !s2.fPoolEscrow);
    BOOST_CHECK_EQUAL(s2.nNoteUnits, 987u);
}

BOOST_AUTO_TEST_CASE(pool_coin_default_ctor_clean)
{
    // A default-constructed Coin must carry NO pool tags: wallet collectors
    // and validation resolvers probe default-constructed Coins, and an
    // uninitialized fPoolEscrow made every probed output read as pool custody
    // (the Gate-2l finding: the default ctor was missed while the two
    // parameterized ctors were extended - pin all three plus Clear()).
    Coin fresh;
    BOOST_CHECK(!fresh.fPoolEscrow);
    BOOST_CHECK(!fresh.fLpShare);
    BOOST_CHECK_EQUAL(fresh.nLpUnits, 0u);

    Coin tagged(CTxOut(POOL_DUST_VALUE, PoolEscrowScript(1)), 100, false, false, false, 0);
    BOOST_CHECK(!tagged.fPoolEscrow && !tagged.fLpShare);
    tagged.SetLpShare(1, 5);
    tagged.Clear();
    BOOST_CHECK(!tagged.fPoolEscrow && !tagged.fLpShare);
    BOOST_CHECK_EQUAL(tagged.nLpUnits, 0u);
}

BOOST_AUTO_TEST_CASE(pool_coin_undo_roundtrip)
{
    // The pool tags must survive the undo format, or a reorg-restored escrow
    // coin re-enters the UTXO set anyone-can-spend.
    Coin coin(CTxOut(POOL_DUST_VALUE, PoolEscrowScript(7)), 100, false, false, false, 0);
    coin.SetNote(7, 123456);
    coin.SetPoolEscrow(7);

    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << TxInUndoSerializer(&coin);
    Coin coin2;
    TxInUndoDeserializer deser(&coin2);
    ss >> deser;
    BOOST_CHECK(coin2.fPoolEscrow);
    BOOST_CHECK(coin2.fNote);
    BOOST_CHECK_EQUAL(coin2.nNoteUnits, 123456u);
    BOOST_CHECK_EQUAL(coin2.nHouseID, 7);

    Coin lp(CTxOut(POOL_DUST_VALUE, PoolScriptForPubKey(PoolFreshPubKey())), 100, false, false, false, 0);
    lp.SetLpShare(9, 777);
    CDataStream ss2(SER_DISK, PROTOCOL_VERSION);
    ss2 << TxInUndoSerializer(&lp);
    Coin lp2;
    TxInUndoDeserializer deser2(&lp2);
    ss2 >> deser2;
    BOOST_CHECK(lp2.fLpShare);
    BOOST_CHECK_EQUAL(lp2.nLpUnits, 777u);
    BOOST_CHECK_EQUAL(lp2.nHouseID, 9);

    // Chainstate (Coin) serialization round-trip too.
    CDataStream ss3(SER_DISK, PROTOCOL_VERSION);
    ss3 << coin;
    Coin coin3;
    ss3 >> coin3;
    BOOST_CHECK(coin3.fPoolEscrow && coin3.fNote);
    BOOST_CHECK_EQUAL(coin3.nNoteUnits, 123456u);
}

// Build a spendable coins view + a structurally valid dir-1 SWAP on pool 7:
// vin[0] = note escrow (X=100000), vin[1] = BTX escrow (Y=100000 sats),
// vin[2] = the trader's 1000-unit note, vin[3] = a plain fee coin.
static CMutableTransaction MakeSwapSetup(CCoinsViewCache& cache, PoolSwap& swap,
                                         const std::vector<unsigned char>& traderPub,
                                         uint32_t nTraderDemandHeight = 0)
{
    swap.nPoolID = 7;
    swap.nPriorNoteReserve = 100000;
    swap.amountPriorBtxReserve = 100000;
    swap.nPriorLpSupply = 100000;
    swap.nDirection = POOL_SWAP_NOTE_TO_BTX;
    swap.nAmountIn = 1000;
    swap.nMinOut = 900;
    swap.nAmountOut = 987;
    swap.nNoteChangeUnits = 0;
    swap.vchTraderPubKey = traderPub;
    swap.vchTraderSig = DummySig();

    Coin escrowNote(CTxOut(POOL_DUST_VALUE, PoolEscrowScript(7)), 100, false, false, false, 0);
    escrowNote.SetNote(7, 100000);
    escrowNote.SetPoolEscrow(7);
    cache.AddCoin(COutPoint(uint256S("0xe0"), 0), std::move(escrowNote), false);

    Coin escrowBtx(CTxOut(100000, PoolEscrowScript(7)), 100, false, false, false, 0);
    escrowBtx.SetPoolEscrow(7);
    cache.AddCoin(COutPoint(uint256S("0xe1"), 0), std::move(escrowBtx), false);

    Coin traderNote(CTxOut(POOL_DUST_VALUE, PoolScriptForPubKey(traderPub)), 100, false, false, false, 0);
    traderNote.SetNote(7, 1000, nTraderDemandHeight);
    cache.AddCoin(COutPoint(uint256S("0xf0"), 0), std::move(traderNote), false);

    Coin feeCoin(CTxOut(10000, PoolScriptForPubKey(traderPub)), 100, false, false, false, 0);
    cache.AddCoin(COutPoint(uint256S("0xf1"), 0), std::move(feeCoin), false);

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_POOL_VERSION;
    mtx.nPoolOp = POOL_OP_SWAP;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xe0"), 0)));
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xe1"), 0)));
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xf0"), 0)));
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xf1"), 0)));
    mtx.vout.emplace_back(POOL_DUST_VALUE, PoolEscrowScript(7));
    mtx.vout.emplace_back(100000 - 987, PoolEscrowScript(7));
    mtx.vout.emplace_back(987, PoolScriptForPubKey(traderPub));
    mtx.vchPoolPayload = EncodePoolPayload(swap);
    return mtx;
}

static std::string PoolInputsReject(const CMutableTransaction& mtx, const CCoinsViewCache& cache)
{
    CValidationState state;
    CAmount fee = 0;
    if (Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee))
        return "OK";
    return state.GetRejectReason();
}

BOOST_AUTO_TEST_CASE(pool_spend_guard)
{
    const std::vector<unsigned char> traderPub = PoolFreshPubKey();

    // Happy path: the structurally valid swap clears CheckTxInputs.
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        PoolSwap swap;
        CMutableTransaction mtx = MakeSwapSetup(cache, swap, traderPub);
        BOOST_CHECK_EQUAL(PoolShapeReject(mtx), "OK");
        BOOST_CHECK_EQUAL(PoolInputsReject(mtx, cache), "OK");
    }

    // A plain tx cannot sweep the anyone-can-spend pool escrow (reserve drain).
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        PoolSwap swap;
        MakeSwapSetup(cache, swap, traderPub);
        CMutableTransaction drain;
        drain.vin.push_back(CTxIn(COutPoint(uint256S("0xe1"), 0)));
        drain.vout.emplace_back(99000, PoolScriptForPubKey(PoolFreshPubKey()));
        BOOST_CHECK_EQUAL(PoolInputsReject(drain, cache), "bad-txns-spend-pool-coin");
    }

    // A plain tx cannot spend an LP coin.
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        Coin lp(CTxOut(POOL_DUST_VALUE, PoolScriptForPubKey(traderPub)), 100, false, false, false, 0);
        lp.SetLpShare(7, 500);
        cache.AddCoin(COutPoint(uint256S("0xaa"), 0), std::move(lp), false);
        CMutableTransaction drain;
        drain.vin.push_back(CTxIn(COutPoint(uint256S("0xaa"), 0)));
        drain.vout.emplace_back(500, PoolScriptForPubKey(PoolFreshPubKey()));
        BOOST_CHECK_EQUAL(PoolInputsReject(drain, cache), "bad-txns-spend-lp-coin");
    }

    // Only UNDEMANDED notes enter a pool (operator decision 4).
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        PoolSwap swap;
        CMutableTransaction mtx = MakeSwapSetup(cache, swap, traderPub, 150 /* demanded */);
        BOOST_CHECK_EQUAL(PoolInputsReject(mtx, cache), "bad-pool-demanded-note");
    }

    // Conservation: trader note units must equal amountIn + change exactly.
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        PoolSwap swap;
        CMutableTransaction mtx = MakeSwapSetup(cache, swap, traderPub);
        swap.nAmountIn = 999;   // inputs carry 1000
        // Keep the escrow output consistent with the lie so only conservation trips.
        mtx.vchPoolPayload = EncodePoolPayload(swap);
        BOOST_CHECK_EQUAL(PoolInputsReject(mtx, cache), "bad-pool-swap-conservation");
    }

    // The escrow pair is positional: note side at vin[0], BTX side at vin[1].
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        PoolSwap swap;
        CMutableTransaction mtx = MakeSwapSetup(cache, swap, traderPub);
        std::swap(mtx.vin[0], mtx.vin[1]);
        BOOST_CHECK_EQUAL(PoolInputsReject(mtx, cache), "bad-pool-escrow-position");
    }

    // The spent custody coin must carry the declared prior X byte-exact.
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        PoolSwap swap;
        CMutableTransaction mtx = MakeSwapSetup(cache, swap, traderPub);
        swap.nPriorNoteReserve = 99999;
        swap.nAmountOut = 987;
        mtx.vchPoolPayload = EncodePoolPayload(swap);
        BOOST_CHECK_EQUAL(PoolInputsReject(mtx, cache), "bad-pool-prior-mismatch");
    }

    // Trader notes must be P2PKH of the DECLARED trader.
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        PoolSwap swap;
        CMutableTransaction mtx = MakeSwapSetup(cache, swap, traderPub);
        swap.vchTraderPubKey = PoolFreshPubKey();   // not the note owner
        mtx.vout[2] = CTxOut(987, PoolScriptForPubKey(swap.vchTraderPubKey));
        mtx.vchPoolPayload = EncodePoolPayload(swap);
        BOOST_CHECK_EQUAL(PoolInputsReject(mtx, cache), "bad-pool-note-input-not-owner");
    }

    // REMOVE_LIQ: LP conservation (burn + change == spent units).
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        Coin escrowNote(CTxOut(POOL_DUST_VALUE, PoolEscrowScript(7)), 100, false, false, false, 0);
        escrowNote.SetNote(7, 100000);
        escrowNote.SetPoolEscrow(7);
        cache.AddCoin(COutPoint(uint256S("0xe0"), 0), std::move(escrowNote), false);
        Coin escrowBtx(CTxOut(100000, PoolEscrowScript(7)), 100, false, false, false, 0);
        escrowBtx.SetPoolEscrow(7);
        cache.AddCoin(COutPoint(uint256S("0xe1"), 0), std::move(escrowBtx), false);
        Coin lp(CTxOut(POOL_DUST_VALUE, PoolScriptForPubKey(traderPub)), 100, false, false, false, 0);
        lp.SetLpShare(7, 5000);
        cache.AddCoin(COutPoint(uint256S("0xaa"), 0), std::move(lp), false);
        Coin feeCoin(CTxOut(10000, PoolScriptForPubKey(traderPub)), 100, false, false, false, 0);
        cache.AddCoin(COutPoint(uint256S("0xac"), 0), std::move(feeCoin), false);

        PoolRemoveLiq rem;
        rem.nPoolID = 7;
        rem.nPriorNoteReserve = 100000;
        rem.amountPriorBtxReserve = 100000;
        rem.nPriorLpSupply = 100000;
        rem.nBurnLp = 4000;                          // spent 5000, change says 0 -> mismatch
        uint64_t noteOut = 0; CAmount btxOut = 0;
        BOOST_CHECK(PoolLpRedeemAmounts(4000, 100000, 100000, 100000, noteOut, btxOut));
        rem.nNoteOut = noteOut;
        rem.amountBtxOut = btxOut;
        rem.nLpChangeUnits = 0;
        rem.vchProviderPubKey = traderPub;
        rem.vchProviderSig = DummySig();

        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_POOL_VERSION;
        mtx.nPoolOp = POOL_OP_REMOVE_LIQ;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xe0"), 0)));
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xe1"), 0)));
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xaa"), 0)));
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xac"), 0)));   // plain funding for the change dust
        mtx.vout.emplace_back(POOL_DUST_VALUE, PoolEscrowScript(7));
        mtx.vout.emplace_back(100000 - btxOut, PoolEscrowScript(7));
        mtx.vout.emplace_back(POOL_DUST_VALUE, PoolScriptForPubKey(traderPub));
        mtx.vout.emplace_back(btxOut, PoolScriptForPubKey(traderPub));
        mtx.vchPoolPayload = EncodePoolPayload(rem);
        BOOST_CHECK_EQUAL(PoolShapeReject(mtx), "OK");
        BOOST_CHECK_EQUAL(PoolInputsReject(mtx, cache), "bad-pool-remove-lp-conservation");

        // Fix the change declaration (needs the LP-change output) -> clears.
        rem.nLpChangeUnits = 1000;
        mtx.vout.emplace_back(POOL_DUST_VALUE, PoolScriptForPubKey(traderPub));
        mtx.vchPoolPayload = EncodePoolPayload(rem);
        BOOST_CHECK_EQUAL(PoolShapeReject(mtx), "OK");
        BOOST_CHECK_EQUAL(PoolInputsReject(mtx, cache), "OK");
    }

    // An asset-colored coin cannot enter a pool op (AddCoins' asset branch
    // would mis-tag the outputs).
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        PoolSwap swap;
        CMutableTransaction mtx = MakeSwapSetup(cache, swap, traderPub);
        Coin asset(CTxOut(5000, PoolScriptForPubKey(traderPub)), 100, false, true, false, 3);
        cache.AddCoin(COutPoint(uint256S("0xab"), 0), std::move(asset), false);
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xab"), 0)));
        BOOST_CHECK_EQUAL(PoolInputsReject(mtx, cache), "bad-pool-colored-input");
    }

    // RETIRE spends the custody pair (op 5 is now an allowed pool-escrow spender)
    // and nothing else; an LP input is rejected (op 5 is not in the fLpShare set).
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        Coin escrowNote(CTxOut(POOL_DUST_VALUE, PoolEscrowScript(7)), 100, false, false, false, 0);
        escrowNote.SetNote(7, 100000);
        escrowNote.SetPoolEscrow(7);
        cache.AddCoin(COutPoint(uint256S("0xe0"), 0), std::move(escrowNote), false);
        Coin escrowBtx(CTxOut(100000, PoolEscrowScript(7)), 100, false, false, false, 0);
        escrowBtx.SetPoolEscrow(7);
        cache.AddCoin(COutPoint(uint256S("0xe1"), 0), std::move(escrowBtx), false);
        Coin feeCoin(CTxOut(20000, PoolScriptForPubKey(traderPub)), 100, false, false, false, 0);
        cache.AddCoin(COutPoint(uint256S("0xac"), 0), std::move(feeCoin), false);

        PoolRetire ret;
        ret.nPoolID = 7;
        ret.nPriorNoteReserve = 100000;
        ret.amountPriorBtxReserve = 100000;
        ret.nPriorLpSupply = POOL_MIN_LIQUIDITY;
        ret.nFeeBps = POOL_FEE_BPS_DEFAULT;
        ret.nCreateHeight = 5;
        ret.vApproverIndex = {0};
        ret.vApproverSig = {DummySig()};

        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_POOL_VERSION;
        mtx.nPoolOp = POOL_OP_RETIRE;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xe0"), 0)));
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xe1"), 0)));
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xac"), 0)));
        mtx.vout.emplace_back(100000, PoolScriptForPubKey(PoolFreshPubKey()));  // floor-BTX payout == Y
        mtx.vchPoolPayload = EncodePoolPayload(ret);
        BOOST_CHECK_EQUAL(PoolShapeReject(mtx), "OK");
        BOOST_CHECK_EQUAL(PoolInputsReject(mtx, cache), "OK");

        // Add an LP coin as an extra input: the fLpShare guard rejects it.
        Coin lp(CTxOut(POOL_DUST_VALUE, PoolScriptForPubKey(traderPub)), 100, false, false, false, 0);
        lp.SetLpShare(7, 500);
        cache.AddCoin(COutPoint(uint256S("0xaa"), 0), std::move(lp), false);
        CMutableTransaction badLp = mtx;
        badLp.vin.push_back(CTxIn(COutPoint(uint256S("0xaa"), 0)));
        BOOST_CHECK_EQUAL(PoolInputsReject(badLp, cache), "bad-txns-spend-lp-coin");
    }
}

//
// T-c4/T-c5: contextual ops (priors, house charter, custody identity, formula).
//

// An effectively-Open house whose single partner holds `key` (threshold 1),
// attested recently enough to be Open at test heights ~1100.
static CHouse MakeOpenPoolHouse(uint32_t nHouseID, const CKey& key)
{
    CHouse house;
    house.nHouseID = nHouseID;
    house.houseID = uint256S("f00d");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 1;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nLastAttestHeight = 1000;
    HousePartner p;
    const CPubKey pub = key.GetPubKey();
    p.vchPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
    p.amountPledge = 100 * COIN;
    p.status = HOUSE_PARTNER_ACTIVE;
    house.vPartner.push_back(p);
    return house;
}

static std::vector<unsigned char> SignHash(const CKey& key, const uint256& hash)
{
    std::vector<unsigned char> vchSig;
    BOOST_REQUIRE(key.Sign(hash, vchSig));
    return vchSig;
}

static std::string PoolCtxReject(const CMutableTransaction& mtx, int nHeight,
                                 const std::function<bool(uint32_t, CPool&)>& fnGetPool,
                                 const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                                 CPool& poolOut)
{
    CValidationState state;
    CHouse houseOut;
    bool fHouseChanged = false, fPoolRetired = false;
    if (CheckPoolOperation(CTransaction(mtx), state, nHeight, fnGetPool, fnGetHouse,
                           poolOut, houseOut, fHouseChanged, fPoolRetired))
        return "OK";
    return state.GetRejectReason();
}

/** RETIRE-aware variant: exposes the burned house + fPoolRetired for the
 * contextual retire tests. */
static std::string PoolCtxRetire(const CMutableTransaction& mtx, int nHeight,
                                 const std::function<bool(uint32_t, CPool&)>& fnGetPool,
                                 const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                                 CHouse& houseOut, bool& fPoolRetired)
{
    CValidationState state;
    CPool poolOut;
    bool fHouseChanged = false;
    fPoolRetired = false;
    if (CheckPoolOperation(CTransaction(mtx), state, nHeight, fnGetPool, fnGetHouse,
                           poolOut, houseOut, fHouseChanged, fPoolRetired))
        return "OK";
    return state.GetRejectReason();
}

BOOST_AUTO_TEST_CASE(pool_contextual_create)
{
    CKey partnerKey, creatorKey;
    partnerKey.MakeNewKey(true);
    creatorKey.MakeNewKey(true);
    const CPubKey creatorPub = creatorKey.GetPubKey();

    const CHouse houseOpen = MakeOpenPoolHouse(7, partnerKey);
    auto fnGetHouse = [&](uint32_t nID, CHouse& h) {
        if (nID != 7) return false;
        h = houseOpen;
        return true;
    };
    auto fnNoPool = [](uint32_t, CPool&) { return false; };

    PoolCreate create;
    create.nPoolID = 7;
    create.nFeeBps = POOL_FEE_BPS_DEFAULT;
    create.nInitNoteUnits = 4000;
    create.amountInitBtx = 4000;
    create.nNoteChangeUnits = 0;
    create.vchCreatorPubKey = std::vector<unsigned char>(creatorPub.begin(), creatorPub.end());

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_POOL_VERSION;
    mtx.nPoolOp = POOL_OP_CREATE;
    AddDummyInputs(mtx, 2);
    mtx.vout.emplace_back(POOL_DUST_VALUE, PoolEscrowScript(7));
    mtx.vout.emplace_back(4000, PoolEscrowScript(7));
    mtx.vout.emplace_back(POOL_DUST_VALUE, PoolScriptForPubKey(create.vchCreatorPubKey));

    // Sign over the REAL prevouts/outputs (payload is outside both hashes).
    const uint256 sighash = PoolCreateSigHash(7, create.nFeeBps, create.nInitNoteUnits,
            create.amountInitBtx, 0, PoolHashPrevouts(CTransaction(mtx)), BillHashOutputs(CTransaction(mtx)));
    create.vchCreatorSig = SignHash(creatorKey, sighash);
    create.vApproverIndex = {0};
    create.vApproverSig = {SignHash(partnerKey, sighash)};
    mtx.vchPoolPayload = EncodePoolPayload(create);

    CPool poolOut;
    BOOST_CHECK_EQUAL(PoolCtxReject(mtx, 1100, fnNoPool, fnGetHouse, poolOut), "OK");
    BOOST_CHECK_EQUAL(poolOut.nPoolID, 7);
    BOOST_CHECK_EQUAL(poolOut.nFeeBps, POOL_FEE_BPS_DEFAULT);
    BOOST_CHECK_EQUAL(poolOut.nNoteReserve, 4000u);
    BOOST_CHECK_EQUAL(poolOut.amountBtxReserve, 4000);
    BOOST_CHECK_EQUAL(poolOut.nLpSupply, 4000u);
    BOOST_CHECK(poolOut.outNote == COutPoint(CTransaction(mtx).GetHash(), 0));
    BOOST_CHECK(poolOut.outBtx == COutPoint(CTransaction(mtx).GetHash(), 1));
    BOOST_CHECK_EQUAL(poolOut.nCreateHeight, 1100);

    // One pool per house, forever.
    auto fnHavePool = [&](uint32_t nID, CPool& p) {
        if (nID != 7) return false;
        p = poolOut;
        return true;
    };
    BOOST_CHECK_EQUAL(PoolCtxReject(mtx, 1100, fnHavePool, fnGetHouse, poolOut), "bad-pool-already-exists");

    // Unknown house.
    auto fnNoHouse = [](uint32_t, CHouse&) { return false; };
    BOOST_CHECK_EQUAL(PoolCtxReject(mtx, 1100, fnNoPool, fnNoHouse, poolOut), "bad-pool-unknown-house");

    // Not effectively Open (missed attestation cadence -> derived Stressed).
    CHouse houseStale = houseOpen;
    houseStale.nLastAttestHeight = 100;
    auto fnGetStale = [&](uint32_t nID, CHouse& h) {
        if (nID != 7) return false;
        h = houseStale;
        return true;
    };
    BOOST_CHECK_EQUAL(PoolCtxReject(mtx, 1100, fnNoPool, fnGetStale, poolOut), "bad-pool-create-house-not-open");

    // A non-partner approver signature is refused (the charter is M-of-N).
    PoolCreate cBad = create;
    cBad.vApproverSig = {SignHash(creatorKey, sighash)};
    CMutableTransaction mtxBad = mtx;
    mtxBad.vchPoolPayload = EncodePoolPayload(cBad);
    BOOST_CHECK_EQUAL(PoolCtxReject(mtxBad, 1100, fnNoPool, fnGetHouse, poolOut), "bad-pool-create-approver");

    // A creator sig over different prevouts is refused (R-i6 binding).
    CMutableTransaction mtxMoved = mtx;
    mtxMoved.vin[1] = CTxIn(COutPoint(uint256S("0xdead"), 3));
    BOOST_CHECK_EQUAL(PoolCtxReject(mtxMoved, 1100, fnNoPool, fnGetHouse, poolOut), "bad-pool-create-approver");
}

BOOST_AUTO_TEST_CASE(pool_contextual_add_remove_swap)
{
    CKey userKey;
    userKey.MakeNewKey(true);
    const CPubKey userPub = userKey.GetPubKey();
    const std::vector<unsigned char> userPubV(userPub.begin(), userPub.end());

    CPool pool;
    pool.nPoolID = 7;
    pool.nFeeBps = 30;
    pool.nNoteReserve = 100000;
    pool.amountBtxReserve = 100000;
    pool.nLpSupply = 100000;
    pool.outNote = COutPoint(uint256S("0xe0"), 0);
    pool.outBtx = COutPoint(uint256S("0xe1"), 0);
    pool.nCreateHeight = 500;

    auto fnGetPool = [&](uint32_t nID, CPool& p) {
        if (nID != 7) return false;
        p = pool;
        return true;
    };
    auto fnNoHouse = [](uint32_t, CHouse&) { return false; };   // only CREATE reads the house

    // --- ADD_LIQ happy path ---
    PoolAddLiq add;
    add.nPoolID = 7;
    add.nPriorNoteReserve = 100000;
    add.amountPriorBtxReserve = 100000;
    add.nPriorLpSupply = 100000;
    add.nAddNoteUnits = 100;
    add.amountAddBtx = 100;
    add.nLpMinted = 100;
    add.nNoteChangeUnits = 0;
    add.vchProviderPubKey = userPubV;

    CMutableTransaction mtxA;
    mtxA.nVersion = TRANSACTION_POOL_VERSION;
    mtxA.nPoolOp = POOL_OP_ADD_LIQ;
    mtxA.vin.push_back(CTxIn(pool.outNote));
    mtxA.vin.push_back(CTxIn(pool.outBtx));
    mtxA.vin.push_back(CTxIn(COutPoint(uint256S("0xf0"), 0)));
    mtxA.vout.emplace_back(POOL_DUST_VALUE, PoolEscrowScript(7));
    mtxA.vout.emplace_back(100100, PoolEscrowScript(7));
    mtxA.vout.emplace_back(POOL_DUST_VALUE, PoolScriptForPubKey(userPubV));
    add.vchProviderSig = SignHash(userKey, PoolAddLiqSigHash(add,
            PoolHashPrevouts(CTransaction(mtxA)), BillHashOutputs(CTransaction(mtxA))));
    mtxA.vchPoolPayload = EncodePoolPayload(add);

    CPool poolOut;
    BOOST_CHECK_EQUAL(PoolCtxReject(mtxA, 1100, fnGetPool, fnNoHouse, poolOut), "OK");
    BOOST_CHECK_EQUAL(poolOut.nNoteReserve, 100100u);
    BOOST_CHECK_EQUAL(poolOut.amountBtxReserve, 100100);
    BOOST_CHECK_EQUAL(poolOut.nLpSupply, 100100u);
    BOOST_CHECK(poolOut.outNote == COutPoint(CTransaction(mtxA).GetHash(), 0));
    BOOST_CHECK_EQUAL(poolOut.nFeeBps, 30);          // immutable
    BOOST_CHECK_EQUAL(poolOut.nCreateHeight, 500);   // immutable

    // Stale priors: the pool moved since this op was signed.
    CPool poolMoved = pool;
    poolMoved.nNoteReserve = 100001;
    auto fnGetMoved = [&](uint32_t nID, CPool& p) {
        if (nID != 7) return false;
        p = poolMoved;
        return true;
    };
    BOOST_CHECK_EQUAL(PoolCtxReject(mtxA, 1100, fnGetMoved, fnNoHouse, poolOut), "bad-pool-priors-mismatch");

    // Wrong custody outpoint: same tags, not THE canonical coin.
    CMutableTransaction mtxWrong = mtxA;
    mtxWrong.vin[0] = CTxIn(COutPoint(uint256S("0xbeef"), 0));
    BOOST_CHECK_EQUAL(PoolCtxReject(mtxWrong, 1100, fnGetPool, fnNoHouse, poolOut), "bad-pool-wrong-escrow-outpoint");

    // Provider sig must bind the payload (flip a field after signing).
    PoolAddLiq addLie = add;
    addLie.nLpMinted = 99;   // formula-consistent? No - but sig check runs first on decode? (contextual order: priors, outpoints, then sig)
    CMutableTransaction mtxLie = mtxA;
    mtxLie.vchPoolPayload = EncodePoolPayload(addLie);
    BOOST_CHECK_EQUAL(PoolCtxReject(mtxLie, 1100, fnGetPool, fnNoHouse, poolOut), "bad-pool-add-sig");

    // Unknown pool.
    auto fnNoPool = [](uint32_t, CPool&) { return false; };
    BOOST_CHECK_EQUAL(PoolCtxReject(mtxA, 1100, fnNoPool, fnNoHouse, poolOut), "bad-pool-unknown-pool");

    // --- SWAP: the formula runs with the STORED fee ---
    PoolSwap swap;
    swap.nPoolID = 7;
    swap.nPriorNoteReserve = 100000;
    swap.amountPriorBtxReserve = 100000;
    swap.nPriorLpSupply = 100000;
    swap.nDirection = POOL_SWAP_NOTE_TO_BTX;
    swap.nAmountIn = 1000;
    swap.nMinOut = 900;
    swap.nAmountOut = 987;   // PoolSwapOut(1000, 100000, 100000, 30)
    swap.nNoteChangeUnits = 0;
    swap.vchTraderPubKey = userPubV;

    CMutableTransaction mtxS;
    mtxS.nVersion = TRANSACTION_POOL_VERSION;
    mtxS.nPoolOp = POOL_OP_SWAP;
    mtxS.vin.push_back(CTxIn(pool.outNote));
    mtxS.vin.push_back(CTxIn(pool.outBtx));
    mtxS.vin.push_back(CTxIn(COutPoint(uint256S("0xf0"), 0)));
    mtxS.vout.emplace_back(POOL_DUST_VALUE, PoolEscrowScript(7));
    mtxS.vout.emplace_back(100000 - 987, PoolEscrowScript(7));
    mtxS.vout.emplace_back(987, PoolScriptForPubKey(userPubV));
    swap.vchTraderSig = SignHash(userKey, PoolSwapSigHash(swap,
            PoolHashPrevouts(CTransaction(mtxS)), BillHashOutputs(CTransaction(mtxS))));
    mtxS.vchPoolPayload = EncodePoolPayload(swap);

    BOOST_CHECK_EQUAL(PoolCtxReject(mtxS, 1100, fnGetPool, fnNoHouse, poolOut), "OK");
    BOOST_CHECK_EQUAL(poolOut.nNoteReserve, 101000u);
    BOOST_CHECK_EQUAL(poolOut.amountBtxReserve, 100000 - 987);
    BOOST_CHECK_EQUAL(poolOut.nLpSupply, 100000u);   // swaps never mint shares

    // A wrong out amount fails the formula (sig re-done so ONLY the formula trips).
    PoolSwap swapBad = swap;
    swapBad.nAmountOut = 986;
    CMutableTransaction mtxSBad = mtxS;
    mtxSBad.vout[1] = CTxOut(100000 - 986, PoolEscrowScript(7));
    mtxSBad.vout[2] = CTxOut(986, PoolScriptForPubKey(userPubV));
    swapBad.vchTraderSig = SignHash(userKey, PoolSwapSigHash(swapBad,
            PoolHashPrevouts(CTransaction(mtxSBad)), BillHashOutputs(CTransaction(mtxSBad))));
    mtxSBad.vchPoolPayload = EncodePoolPayload(swapBad);
    BOOST_CHECK_EQUAL(PoolCtxReject(mtxSBad, 1100, fnGetPool, fnNoHouse, poolOut), "bad-pool-swap-formula");

    // Direction 2 happy path: sats in, notes out, same formula both ways.
    PoolSwap swap2;
    swap2.nPoolID = 7;
    swap2.nPriorNoteReserve = 100000;
    swap2.amountPriorBtxReserve = 100000;
    swap2.nPriorLpSupply = 100000;
    swap2.nDirection = POOL_SWAP_BTX_TO_NOTE;
    swap2.nAmountIn = 1000;
    swap2.nMinOut = 900;
    swap2.nAmountOut = 987;
    swap2.nNoteChangeUnits = 0;
    swap2.vchTraderPubKey = userPubV;

    CMutableTransaction mtxS2;
    mtxS2.nVersion = TRANSACTION_POOL_VERSION;
    mtxS2.nPoolOp = POOL_OP_SWAP;
    mtxS2.vin.push_back(CTxIn(pool.outNote));
    mtxS2.vin.push_back(CTxIn(pool.outBtx));
    mtxS2.vin.push_back(CTxIn(COutPoint(uint256S("0xf1"), 0)));
    mtxS2.vout.emplace_back(POOL_DUST_VALUE, PoolEscrowScript(7));
    mtxS2.vout.emplace_back(101000, PoolEscrowScript(7));
    mtxS2.vout.emplace_back(POOL_DUST_VALUE, PoolScriptForPubKey(userPubV));
    swap2.vchTraderSig = SignHash(userKey, PoolSwapSigHash(swap2,
            PoolHashPrevouts(CTransaction(mtxS2)), BillHashOutputs(CTransaction(mtxS2))));
    mtxS2.vchPoolPayload = EncodePoolPayload(swap2);

    BOOST_CHECK_EQUAL(PoolCtxReject(mtxS2, 1100, fnGetPool, fnNoHouse, poolOut), "OK");
    BOOST_CHECK_EQUAL(poolOut.nNoteReserve, 100000u - 987u);
    BOOST_CHECK_EQUAL(poolOut.amountBtxReserve, 101000);

    // --- REMOVE_LIQ happy path ---
    PoolRemoveLiq rem;
    rem.nPoolID = 7;
    rem.nPriorNoteReserve = 100000;
    rem.amountPriorBtxReserve = 100000;
    rem.nPriorLpSupply = 100000;
    rem.nBurnLp = 5000;
    rem.nNoteOut = 5000;
    rem.amountBtxOut = 5000;
    rem.nLpChangeUnits = 0;
    rem.vchProviderPubKey = userPubV;

    CMutableTransaction mtxR;
    mtxR.nVersion = TRANSACTION_POOL_VERSION;
    mtxR.nPoolOp = POOL_OP_REMOVE_LIQ;
    mtxR.vin.push_back(CTxIn(pool.outNote));
    mtxR.vin.push_back(CTxIn(pool.outBtx));
    mtxR.vin.push_back(CTxIn(COutPoint(uint256S("0xaa"), 0)));
    mtxR.vout.emplace_back(POOL_DUST_VALUE, PoolEscrowScript(7));
    mtxR.vout.emplace_back(95000, PoolEscrowScript(7));
    mtxR.vout.emplace_back(POOL_DUST_VALUE, PoolScriptForPubKey(userPubV));
    mtxR.vout.emplace_back(5000, PoolScriptForPubKey(userPubV));
    rem.vchProviderSig = SignHash(userKey, PoolRemoveLiqSigHash(rem,
            PoolHashPrevouts(CTransaction(mtxR)), BillHashOutputs(CTransaction(mtxR))));
    mtxR.vchPoolPayload = EncodePoolPayload(rem);

    BOOST_CHECK_EQUAL(PoolCtxReject(mtxR, 1100, fnGetPool, fnNoHouse, poolOut), "OK");
    BOOST_CHECK_EQUAL(poolOut.nNoteReserve, 95000u);
    BOOST_CHECK_EQUAL(poolOut.amountBtxReserve, 95000);
    BOOST_CHECK_EQUAL(poolOut.nLpSupply, 95000u);
}

BOOST_AUTO_TEST_CASE(pool_contextual_retire)
{
    CKey partnerKey, redeemKey;
    partnerKey.MakeNewKey(true);
    redeemKey.MakeNewKey(true);
    const CPubKey redeemPub = redeemKey.GetPubKey();
    const std::vector<unsigned char> redeemPubV(redeemPub.begin(), redeemPub.end());

    // A floored pool: all issued LP removed, only the never-issued locked floor
    // (S == POOL_MIN_LIQUIDITY) remains. Its residual X + Y back nobody.
    CPool pool;
    pool.nPoolID = 7;
    pool.nFeeBps = 30;
    pool.nNoteReserve = 5000;
    pool.amountBtxReserve = 5000;
    pool.nLpSupply = POOL_MIN_LIQUIDITY;
    pool.outNote = COutPoint(uint256S("0xe0"), 0);
    pool.outBtx = COutPoint(uint256S("0xe1"), 0);
    pool.nCreateHeight = 500;
    auto fnGetPool = [&](uint32_t nID, CPool& p) {
        if (nID != 7) return false;
        p = pool; return true;
    };

    CHouse houseOpen = MakeOpenPoolHouse(7, partnerKey);
    houseOpen.nMintedUnits = 5000;                 // exactly the residual -> burns to 0
    houseOpen.vchRedemptionDestPK = redeemPubV;
    auto fnGetHouse = [&](uint32_t nID, CHouse& h) {
        if (nID != 7) return false;
        h = houseOpen; return true;
    };

    // Every RETIRE tx here shares the custody pair + a plain fee input + the
    // forced floor-BTX payout (P2PKH(redeemPubV), value == Y). Only the payload
    // differs, and neither hashPrevouts nor hashOutputs depends on the payload.
    auto buildRetire = [&](const PoolRetire& payload) {
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_POOL_VERSION;
        mtx.nPoolOp = POOL_OP_RETIRE;
        mtx.vin.push_back(CTxIn(pool.outNote));
        mtx.vin.push_back(CTxIn(pool.outBtx));
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xf0"), 0)));
        mtx.vout.emplace_back(5000, PoolScriptForPubKey(redeemPubV));
        mtx.vchPoolPayload = EncodePoolPayload(payload);
        return mtx;
    };

    PoolRetire tmpl;
    tmpl.nPoolID = 7;
    tmpl.nPriorNoteReserve = 5000;
    tmpl.amountPriorBtxReserve = 5000;
    tmpl.nPriorLpSupply = POOL_MIN_LIQUIDITY;
    tmpl.nFeeBps = 30;
    tmpl.nCreateHeight = 500;

    const CMutableTransaction mtxTmpl = buildRetire(tmpl);
    const uint256 sighash = PoolRetireSigHash(tmpl,
            PoolHashPrevouts(CTransaction(mtxTmpl)), BillHashOutputs(CTransaction(mtxTmpl)));

    // --- M-of-N happy path (valid at effective Open) ---
    PoolRetire mn = tmpl;
    mn.vApproverIndex = {0};
    mn.vApproverSig = {SignHash(partnerKey, sighash)};
    const CMutableTransaction mtx = buildRetire(mn);

    CHouse houseOut;
    bool fRetired = false;
    BOOST_CHECK_EQUAL(PoolCtxRetire(mtx, 1100, fnGetPool, fnGetHouse, houseOut, fRetired), "OK");
    BOOST_CHECK(fRetired);
    BOOST_CHECK_EQUAL(houseOut.nMintedUnits, 0u);   // liabilities reach 0 -> WINDDOWN/settle reachable

    // Unknown pool.
    auto fnNoPool = [](uint32_t, CPool&) { return false; };
    BOOST_CHECK_EQUAL(PoolCtxRetire(mtx, 1100, fnNoPool, fnGetHouse, houseOut, fRetired), "bad-pool-unknown-pool");

    // Priors mismatch (fee differs from the record - the payload carries the full
    // prior record so undo is payload-only).
    {
        PoolRetire r = mn; r.nFeeBps = 31;
        CMutableTransaction bad = buildRetire(r);
        BOOST_CHECK_EQUAL(PoolCtxRetire(bad, 1100, fnGetPool, fnGetHouse, houseOut, fRetired), "bad-pool-retire-priors-mismatch");
    }

    // Not at the floor: record AND payload agree on S = MIN+1 (priors match), so
    // the dedicated floor gate rejects.
    {
        CPool poolAbove = pool; poolAbove.nLpSupply = POOL_MIN_LIQUIDITY + 1;
        auto fnAbove = [&](uint32_t nID, CPool& p){ if (nID != 7) return false; p = poolAbove; return true; };
        PoolRetire r = mn; r.nPriorLpSupply = POOL_MIN_LIQUIDITY + 1;
        CMutableTransaction bad = buildRetire(r);
        BOOST_CHECK_EQUAL(PoolCtxRetire(bad, 1100, fnAbove, fnGetHouse, houseOut, fRetired), "bad-pool-retire-not-floor");
    }

    // Custody outpoint mismatch (vin[0] is not the record's outNote); the outpoint
    // check runs before auth.
    {
        CMutableTransaction bad = mtx;
        bad.vin[0] = CTxIn(COutPoint(uint256S("0xbeef"), 1));
        BOOST_CHECK_EQUAL(PoolCtxRetire(bad, 1100, fnGetPool, fnGetHouse, houseOut, fRetired), "bad-pool-wrong-escrow-outpoint");
    }

    // Underflow: house.nMintedUnits < X.
    {
        CHouse houseLow = houseOpen; houseLow.nMintedUnits = 4999;
        auto fnLow = [&](uint32_t nID, CHouse& h){ if (nID != 7) return false; h = houseLow; return true; };
        BOOST_CHECK_EQUAL(PoolCtxRetire(mtx, 1100, fnGetPool, fnLow, houseOut, fRetired), "bad-pool-retire-underflow");
    }

    // M-of-N approver signature by a non-partner key.
    {
        PoolRetire r = mn;
        r.vApproverSig = {SignHash(redeemKey, sighash)};
        CMutableTransaction bad = buildRetire(r);
        BOOST_CHECK_EQUAL(PoolCtxRetire(bad, 1100, fnGetPool, fnGetHouse, houseOut, fRetired), "bad-pool-retire-approver");
    }

    // Wrong payout destination (auth valid, but vout[0] is not P2PKH(destPK)).
    {
        CMutableTransaction bad = buildRetire(mn);
        bad.vout[0] = CTxOut(5000, PoolScriptForPubKey(PoolFreshPubKey()));
        PoolRetire r = mn;
        r.vApproverSig = {SignHash(partnerKey, PoolRetireSigHash(r,
                PoolHashPrevouts(CTransaction(bad)), BillHashOutputs(CTransaction(bad))))};
        bad.vchPoolPayload = EncodePoolPayload(r);
        BOOST_CHECK_EQUAL(PoolCtxRetire(bad, 1100, fnGetPool, fnGetHouse, houseOut, fRetired), "bad-pool-retire-payout");
    }

    // --- Single-partner path: rejected at effective Open, accepted at Insolvent ---
    PoolRetire sp = tmpl;
    sp.nTriggerPartnerIndex = 0;
    sp.vchTriggerSig = SignHash(partnerKey, PoolRetireSigHash(sp,
            PoolHashPrevouts(CTransaction(mtxTmpl)), BillHashOutputs(CTransaction(mtxTmpl))));
    const CMutableTransaction spTx = buildRetire(sp);
    BOOST_CHECK_EQUAL(PoolCtxRetire(spTx, 1100, fnGetPool, fnGetHouse, houseOut, fRetired),
                      "bad-pool-retire-trigger-not-insolvent");

    CHouse houseInsolvent = houseOpen;
    houseInsolvent.status = HOUSE_STATUS_INSOLVENT;   // materialized -> effective Insolvent
    auto fnInsolvent = [&](uint32_t nID, CHouse& h){ if (nID != 7) return false; h = houseInsolvent; return true; };
    BOOST_CHECK_EQUAL(PoolCtxRetire(spTx, 1100, fnGetPool, fnInsolvent, houseOut, fRetired), "OK");
    BOOST_CHECK(fRetired);
    BOOST_CHECK_EQUAL(houseOut.nMintedUnits, 0u);

    // A SETTLED trigger partner may not fire the single-partner path.
    {
        CHouse h = houseInsolvent;
        h.vPartner[0].status = HOUSE_PARTNER_SETTLED;
        auto fnSettled = [&](uint32_t nID, CHouse& hh){ if (nID != 7) return false; hh = h; return true; };
        BOOST_CHECK_EQUAL(PoolCtxRetire(spTx, 1100, fnGetPool, fnSettled, houseOut, fRetired), "bad-pool-retire-trigger-settled");
    }
}

BOOST_AUTO_TEST_SUITE_END()
