// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <house.h>

#include <coins.h>
#include <consensus/validation.h>
#include <key.h>
#include <note.h>
#include <script/standard.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <utilstrencodings.h>
#include <version.h>

#include <functional>

#include <boost/test/unit_test.hpp>

// Contextual house-op validator (validation.cpp, external linkage; not in a
// public header). Forward-declared here so the negative direction of every 3.5
// consensus guard - previously reachable only through the wallet, which never
// builds a rejectable tx - can be exercised directly (R-i6 test-quality fixes).
bool CheckHouseOperation(const CTransaction& tx, CValidationState& state, int nHeight,
                         const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                         const std::function<bool(const uint256&)>& fnHaveHouseHash,
                         const std::function<bool(const std::string&)>& fnHaveClassID,
                         const std::function<bool(const COutPoint&, Coin&)>& fnGetProofCoin,
                         const std::function<bool(uint32_t, uint256&)>& fnGetBlockHash,
                         CHouse& houseOut);

BOOST_FIXTURE_TEST_SUITE(house_tests, BasicTestingSetup)

// Build a fully valid REGISTER tx for nPartners partners at the given tier
static CMutableTransaction MakeRegisterTx(HouseRegister& regOut, std::vector<CKey>& vKey,
                                          uint8_t nTier, uint32_t nThresholdM, size_t nPartners,
                                          const std::string& strClassID = "clyde")
{
    HouseRegister reg;
    reg.nTier = nTier;
    reg.nThresholdM = nThresholdM;
    reg.strClassID = strClassID;
    reg.nDenomMgGold = 1000;

    CKey keyRedemption;
    keyRedemption.MakeNewKey(true);
    CPubKey pubRedemption = keyRedemption.GetPubKey();
    reg.vchRedemptionDestPK = std::vector<unsigned char>(pubRedemption.begin(), pubRedemption.end());

    vKey.clear();
    for (size_t i = 0; i < nPartners; i++) {
        CKey key;
        key.MakeNewKey(true);
        CPubKey pub = key.GetPubKey();
        reg.vPartnerPubKey.push_back(std::vector<unsigned char>(pub.begin(), pub.end()));
        reg.vPledgeAmount.push_back(HOUSE_MIN_PLEDGE * (i + 1));
        vKey.push_back(key);
    }

    const uint256 declDigest = HouseDeclarationDigest(reg);
    for (size_t i = 0; i < nPartners; i++) {
        std::vector<unsigned char> vchSig;
        BOOST_REQUIRE(vKey[i].Sign(HouseRegisterSigHash(declDigest, i, reg.vPledgeAmount[i]), vchSig));
        reg.vPartnerSig.push_back(vchSig);
    }

    const uint256 houseID = HouseIDFromDeclaration(reg);

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_REGISTER;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << reg;
    mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());

    // funding input placeholder (prevout must be non-null for CheckTransaction)
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));

    for (size_t i = 0; i < nPartners; i++)
        mtx.vout.push_back(CTxOut(reg.vPledgeAmount[i], HouseEscrowScript(houseID)));

    regOut = reg;
    return mtx;
}

BOOST_AUTO_TEST_CASE(house_id_derivation)
{
    // Content-derived, deterministic, and sensitive to every declaration field
    HouseRegister reg;
    std::vector<CKey> vKey;
    MakeRegisterTx(reg, vKey, HOUSE_TIER_BONDED_SOLO, 1, 1);

    const uint256 id1 = HouseIDFromDeclaration(reg);
    BOOST_CHECK(!id1.IsNull());
    BOOST_CHECK(HouseIDFromDeclaration(reg) == id1);

    HouseRegister reg2 = reg;
    reg2.strClassID = "other";
    BOOST_CHECK(HouseIDFromDeclaration(reg2) != id1);

    HouseRegister reg3 = reg;
    reg3.vPledgeAmount[0] += 1;
    BOOST_CHECK(HouseIDFromDeclaration(reg3) != id1);
}

BOOST_AUTO_TEST_CASE(house_sighash_domain_separation)
{
    // Every op sighash must differ for identical field values
    const uint256 h = uint256S("aa");
    std::vector<unsigned char> pk(33, 0x02);

    const uint256 outs = uint256S("cc");
    std::vector<uint256> v;
    v.push_back(HouseRegisterSigHash(h, 0, 1000));
    v.push_back(HouseTopupSigHash(h, 0, h));
    v.push_back(HouseAdmitSigHash(h, pk, 1000));
    v.push_back(HouseExitSigHash(h, 0, outs));
    v.push_back(HouseWinddownSigHash(h, outs));
    v.push_back(HouseReclaimSigHash(h, 0, h));

    for (size_t i = 0; i < v.size(); i++) {
        for (size_t j = i + 1; j < v.size(); j++)
            BOOST_CHECK(v[i] != v[j]);
    }

    // And distinct from the bill domain (same-family escrow scripts)
    BOOST_CHECK(HouseWinddownSigHash(h, outs) != HouseExitSigHash(h, 0, outs));

    // Exit/winddown sighashes must actually vary with the output set (freshness)
    BOOST_CHECK(HouseExitSigHash(h, 0, outs) != HouseExitSigHash(h, 0, uint256S("dd")));
    BOOST_CHECK(HouseWinddownSigHash(h, outs) != HouseWinddownSigHash(h, uint256S("dd")));
}

BOOST_AUTO_TEST_CASE(house_escrow_script)
{
    const uint256 houseID = uint256S("1234");
    const CScript script = HouseEscrowScript(houseID);
    BOOST_CHECK(IsHouseEscrowScript(script));
    BOOST_CHECK_EQUAL(script.size(), 35);

    BOOST_CHECK(!IsHouseEscrowScript(CScript()));
    BOOST_CHECK(!IsHouseEscrowScript(CScript() << OP_TRUE));
}

BOOST_AUTO_TEST_CASE(house_class_id_rules)
{
    BOOST_CHECK(IsValidHouseClassID("clyde"));
    BOOST_CHECK(IsValidHouseClassID("a"));
    BOOST_CHECK(IsValidHouseClassID("x123abc"));
    BOOST_CHECK(IsValidHouseClassID("0123456789abcdef"));   // 16 chars

    BOOST_CHECK(!IsValidHouseClassID(""));
    BOOST_CHECK(!IsValidHouseClassID("0123456789abcdefg"));  // 17
    BOOST_CHECK(!IsValidHouseClassID("Clyde"));              // uppercase
    BOOST_CHECK(!IsValidHouseClassID("cly de"));             // space
    BOOST_CHECK(!IsValidHouseClassID("cly-de"));             // punctuation
}

BOOST_AUTO_TEST_CASE(house_payload_roundtrip)
{
    HouseRegister reg;
    std::vector<CKey> vKey;
    MakeRegisterTx(reg, vKey, HOUSE_TIER_MULTI_PARTNER, 2, 3);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << reg;
    HouseRegister reg2;
    BOOST_REQUIRE(DecodeHousePayload(std::vector<unsigned char>(ss.begin(), ss.end()), reg2));
    BOOST_CHECK_EQUAL(reg2.nTier, reg.nTier);
    BOOST_CHECK_EQUAL(reg2.nThresholdM, reg.nThresholdM);
    BOOST_CHECK_EQUAL(reg2.strClassID, reg.strClassID);
    BOOST_CHECK(reg2.vPartnerPubKey == reg.vPartnerPubKey);
    BOOST_CHECK(reg2.vPledgeAmount == reg.vPledgeAmount);

    // Trailing bytes rejected
    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
    ss2 << reg;
    ss2 << uint8_t(0xff);
    BOOST_CHECK(!DecodeHousePayload(std::vector<unsigned char>(ss2.begin(), ss2.end()), reg2));

    // The other payloads round-trip too
    HouseReclaim rec;
    rec.nHouseID = 7;
    rec.nPartnerIndex = 2;
    rec.vchSig = std::vector<unsigned char>(70, 0x30);
    CDataStream ss3(SER_NETWORK, PROTOCOL_VERSION);
    ss3 << rec;
    HouseReclaim rec2;
    BOOST_REQUIRE(DecodeHousePayload(std::vector<unsigned char>(ss3.begin(), ss3.end()), rec2));
    BOOST_CHECK_EQUAL(rec2.nHouseID, 7);
    BOOST_CHECK_EQUAL(rec2.nPartnerIndex, 2);
}

BOOST_AUTO_TEST_CASE(house_tx_serialization_roundtrip)
{
    HouseRegister reg;
    std::vector<CKey> vKey;
    CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_RESTRICTED, 2, 2);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << mtx;
    CMutableTransaction mtx2;
    ss >> mtx2;
    BOOST_CHECK_EQUAL(mtx2.nVersion, TRANSACTION_HOUSE_VERSION);
    BOOST_CHECK_EQUAL(mtx2.nHouseOp, HOUSE_OP_REGISTER);
    BOOST_CHECK(mtx2.vchHousePayload == mtx.vchHousePayload);
    BOOST_CHECK(CTransaction(mtx2).GetHash() == CTransaction(mtx).GetHash());
}

BOOST_AUTO_TEST_CASE(house_register_shape_valid)
{
    // All four tiers pass the context-free shape checks
    CValidationState state;
    HouseRegister reg;
    std::vector<CKey> vKey;

    BOOST_CHECK(CheckHouseTransactionShape(CTransaction(MakeRegisterTx(reg, vKey, HOUSE_TIER_BONDED_SOLO, 1, 1, "t0solo")), state));
    BOOST_CHECK(CheckHouseTransactionShape(CTransaction(MakeRegisterTx(reg, vKey, HOUSE_TIER_ENCUMBERED_SOLO, 1, 1, "t1solo")), state));
    BOOST_CHECK(CheckHouseTransactionShape(CTransaction(MakeRegisterTx(reg, vKey, HOUSE_TIER_RESTRICTED, 2, 2, "t2multi")), state));
    BOOST_CHECK(CheckHouseTransactionShape(CTransaction(MakeRegisterTx(reg, vKey, HOUSE_TIER_MULTI_PARTNER, 3, 5, "t3multi")), state));
}

BOOST_AUTO_TEST_CASE(house_register_shape_rejections)
{
    CValidationState state;
    HouseRegister reg;
    std::vector<CKey> vKey;

    // Solo with 2 partners
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_BONDED_SOLO, 1, 2);
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    // Multi with 1 partner
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_MULTI_PARTNER, 1, 1);
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    // Multi-partner tier with threshold M=1 (single-point control) rejected
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_MULTI_PARTNER, 1, 3);
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_RESTRICTED, 1, 2);
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    // Threshold above the set size
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_MULTI_PARTNER, 4, 3);
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    // Bad class id
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_BONDED_SOLO, 1, 1, "BADID");
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    // Pledge below floor: rebuild payload with a sub-minimum pledge
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_BONDED_SOLO, 1, 1);
        HouseRegister bad = reg;
        bad.vPledgeAmount[0] = HOUSE_MIN_PLEDGE - 1;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << bad;
        mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vout[0].nValue = HOUSE_MIN_PLEDGE - 1;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    // Escrow output value mismatching the declared pledge
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_BONDED_SOLO, 1, 1);
        mtx.vout[0].nValue += 1;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    // Duplicate partner key
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_RESTRICTED, 2, 2);
        HouseRegister bad = reg;
        bad.vPartnerPubKey[1] = bad.vPartnerPubKey[0];
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << bad;
        mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        const uint256 houseID = HouseIDFromDeclaration(bad);
        mtx.vout[0].scriptPubKey = HouseEscrowScript(houseID);
        mtx.vout[1].scriptPubKey = HouseEscrowScript(houseID);
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    // Zero denomination
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_BONDED_SOLO, 1, 1);
        HouseRegister bad = reg;
        bad.nDenomMgGold = 0;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << bad;
        mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        const uint256 houseID = HouseIDFromDeclaration(bad);
        mtx.vout[0].scriptPubKey = HouseEscrowScript(houseID);
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
}

BOOST_AUTO_TEST_CASE(house_approver_shape_rules)
{
    // Exercised through the ADMIT shape path: duplicate / descending approver
    // indices and mismatched sig arrays must be rejected
    CValidationState state;

    HouseAdmit admit;
    admit.nHouseID = 1;
    CKey keyNew;
    keyNew.MakeNewKey(true);
    CPubKey pubNew = keyNew.GetPubKey();
    admit.vchNewPubKey = std::vector<unsigned char>(pubNew.begin(), pubNew.end());
    admit.vchNewSig = std::vector<unsigned char>(70, 0x30);
    admit.vApproverIndex = {0, 1};
    admit.vApproverSig = {std::vector<unsigned char>(70, 0x30), std::vector<unsigned char>(70, 0x30)};

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_ADMIT;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
    mtx.vout.push_back(CTxOut(HOUSE_MIN_PLEDGE, HouseEscrowScript(uint256S("aa"))));

    auto encode = [&](const HouseAdmit& a) {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << a;
        mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    };

    encode(admit);
    BOOST_CHECK(CheckHouseTransactionShape(CTransaction(mtx), state));

    // Duplicate index
    HouseAdmit bad = admit;
    bad.vApproverIndex = {1, 1};
    encode(bad);
    BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));

    // Descending order
    bad = admit;
    bad.vApproverIndex = {1, 0};
    encode(bad);
    BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));

    // Sig / index count mismatch
    bad = admit;
    bad.vApproverSig.pop_back();
    encode(bad);
    BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));

    // No approvers at all
    bad = admit;
    bad.vApproverIndex.clear();
    bad.vApproverSig.clear();
    encode(bad);
    BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
}

BOOST_AUTO_TEST_CASE(house_register_sig_binding)
{
    // A founding signature must break if the declaration or the signer's own
    // pledge amount changes (anti front-run binding)
    HouseRegister reg;
    std::vector<CKey> vKey;
    MakeRegisterTx(reg, vKey, HOUSE_TIER_RESTRICTED, 2, 2);

    const uint256 declDigest = HouseDeclarationDigest(reg);
    const uint256 sighash = HouseRegisterSigHash(declDigest, 0, reg.vPledgeAmount[0]);
    BOOST_CHECK(CPubKey(reg.vPartnerPubKey[0]).Verify(sighash, reg.vPartnerSig[0]));

    // Different pledge -> different sighash -> signature no longer verifies
    const uint256 sighashBad = HouseRegisterSigHash(declDigest, 0, reg.vPledgeAmount[0] + 1);
    BOOST_CHECK(!CPubKey(reg.vPartnerPubKey[0]).Verify(sighashBad, reg.vPartnerSig[0]));

    // Different partner index (same amount) also breaks
    const uint256 sighashIdx = HouseRegisterSigHash(declDigest, 1, reg.vPledgeAmount[0]);
    BOOST_CHECK(!CPubKey(reg.vPartnerPubKey[0]).Verify(sighashIdx, reg.vPartnerSig[0]));

    // Mutated declaration (class id) breaks every founding signature
    HouseRegister reg2 = reg;
    reg2.strClassID = "other";
    const uint256 declDigest2 = HouseDeclarationDigest(reg2);
    const uint256 sighash2 = HouseRegisterSigHash(declDigest2, 0, reg2.vPledgeAmount[0]);
    BOOST_CHECK(!CPubKey(reg.vPartnerPubKey[0]).Verify(sighash2, reg.vPartnerSig[0]));
}

BOOST_AUTO_TEST_CASE(house_record_serialization)
{
    CHouse house;
    house.nHouseID = 42;
    house.houseID = uint256S("beef");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 2;
    house.strClassID = "ayr";
    house.nDenomMgGold = 1000;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 100;

    HousePartner p1;
    p1.vchPubKey = std::vector<unsigned char>(33, 0x02);
    p1.amountPledge = HOUSE_MIN_PLEDGE;
    p1.vOutPledge.push_back(COutPoint(uint256S("aa"), 0));
    p1.status = HOUSE_PARTNER_ACTIVE;

    HousePartner p2 = p1;
    p2.status = HOUSE_PARTNER_TAIL;
    p2.nTailUnlockHeight = 158000;

    house.vPartner.push_back(p1);
    house.vPartner.push_back(p2);

    // Active-escrow counts ACTIVE pledges only (CM-2)
    BOOST_CHECK_EQUAL(house.ActiveEscrow(), HOUSE_MIN_PLEDGE);
    BOOST_CHECK_EQUAL(house.ActivePartnerCount(), 1);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << house;
    CHouse house2;
    ss >> house2;
    BOOST_CHECK_EQUAL(house2.nHouseID, 42);
    BOOST_CHECK_EQUAL(house2.strClassID, "ayr");
    BOOST_CHECK_EQUAL(house2.vPartner.size(), 2);
    BOOST_CHECK_EQUAL(house2.vPartner[1].status, HOUSE_PARTNER_TAIL);
    BOOST_CHECK_EQUAL(house2.vPartner[1].nTailUnlockHeight, 158000);
    BOOST_CHECK_EQUAL(house2.ActiveEscrow(), HOUSE_MIN_PLEDGE);
}

BOOST_AUTO_TEST_CASE(house_serialization_v2_attest_fields)
{
    // 3.4 fields round-trip; version byte guards the layout (D10)
    CHouse house;
    house.nHouseID = 7;
    house.strClassID = "paisley";
    {
        HousePartner p;
        p.vchPubKey = std::vector<unsigned char>(33, 0x02);
        p.amountPledge = HOUSE_MIN_PLEDGE;
        p.amountInsolventPledge = 12345;   // residual weight (review fix)
        house.vPartner.push_back(p);
    }
    house.nLastAttestHeight = 5000;
    house.amountLastAttestReserves = 123456789;
    house.nStressSinceHeight = 5100;
    house.nInsolventHeight = 6108;
    house.nInsolventUnits = 300000;
    house.amountInsolventPot = 100000000;
    house.vOutEscrowChange.push_back(COutPoint(uint256S("cc"), 1));

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << house;
    // First byte on the wire is the serialization version
    BOOST_CHECK_EQUAL((uint8_t)ss[0], HOUSE_SER_VERSION);

    CHouse h2;
    ss >> h2;
    BOOST_CHECK_EQUAL(h2.nLastAttestHeight, 5000);
    BOOST_CHECK_EQUAL(h2.amountLastAttestReserves, 123456789);
    BOOST_CHECK_EQUAL(h2.nStressSinceHeight, 5100);
    BOOST_CHECK_EQUAL(h2.nInsolventHeight, 6108);
    BOOST_CHECK_EQUAL(h2.nInsolventUnits, 300000);
    BOOST_CHECK_EQUAL(h2.amountInsolventPot, 100000000);
    BOOST_CHECK_EQUAL(h2.vOutEscrowChange.size(), 1);
    BOOST_CHECK(h2.vOutEscrowChange[0] == COutPoint(uint256S("cc"), 1));
    BOOST_REQUIRE_EQUAL(h2.vPartner.size(), 1);
    BOOST_CHECK_EQUAL(h2.vPartner[0].amountInsolventPledge, 12345);

    // An unknown (FUTURE) version byte is a hard read failure, never defaulted
    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
    ss2 << house;
    ss2[0] = (char)(HOUSE_SER_VERSION + 1);
    CHouse h3;
    BOOST_CHECK_THROW(ss2 >> h3, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(house_serialization_v5_deposit_fields)
{
    // Phase 3.8 term-deposit accounting round-trips, including the 128-bit
    // weighted-maturity accumulator (which overflows u64: one term is
    // principal <= MAX_MONEY times a maturity height).
    CHouse house;
    house.nHouseID = 9;
    house.strClassID = "glasgow";
    house.nMintedUnits = 700000000;
    house.nDepositUnits = 250000000;
    house.nInsolventDepositPrincipal = 40000000;
    const unsigned __int128 wt =
        (unsigned __int128)2000000000000000ULL * (unsigned __int128)1500000ULL; // ~3e21 > 2^64
    house.SetDepositWtMaturity(wt);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << house;
    BOOST_CHECK_EQUAL((uint8_t)ss[0], HOUSE_SER_VERSION);   // 5

    CHouse h2;
    ss >> h2;
    BOOST_CHECK_EQUAL(h2.nMintedUnits, 700000000);
    BOOST_CHECK_EQUAL(h2.nDepositUnits, 250000000);
    BOOST_CHECK_EQUAL(h2.nInsolventDepositPrincipal, 40000000);
    BOOST_CHECK(h2.DepositWtMaturity() == wt);
    BOOST_CHECK_EQUAL(h2.nDepositWtMatHi, (uint64_t)(wt >> 64));
    BOOST_CHECK_EQUAL(h2.nDepositWtMatLo, (uint64_t)wt);
}

BOOST_AUTO_TEST_CASE(house_v4_to_v5_migration)
{
    // A pre-3.8 (v4) record - no deposit leg - must still read, with the deposit
    // fields defaulting to 0. We synthesise a v4 stream from a v5 one whose
    // deposit fields are 0: the trailing 32 bytes (four zeroed u64) are exactly
    // the v5 addendum, so dropping them + stamping version 4 yields a valid v4
    // record. (This is the no-wipe upgrade path for the live HouseDB.)
    CHouse house;
    house.nHouseID = 11;
    house.strClassID = "ayr2";
    house.nMintedUnits = 123456;
    house.nLastAttestHeight = 4321;
    house.amountLastAttestReserves = 99999999;
    house.vOutReserveLock.push_back(COutPoint(uint256S("ab"), 0));
    // deposit fields left at their constructor default of 0

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << house;
    std::vector<char> bytes(ss.begin(), ss.end());
    BOOST_REQUIRE_EQUAL((uint8_t)bytes[0], (uint8_t)6);
    bytes[0] = (char)4;                 // stamp as v4
    // Drop the v5 addendum (four zeroed u64 deposit fields, 32B) AND the v6
    // addendum (zeroed u32 nDeferEndedHeight, 4B) - both post-date v4.
    bytes.resize(bytes.size() - 36);

    CDataStream ssV4(bytes, SER_NETWORK, PROTOCOL_VERSION);
    CHouse h2;
    ssV4 >> h2;                         // must not throw
    BOOST_CHECK_EQUAL(h2.nHouseID, 11);
    BOOST_CHECK_EQUAL(h2.strClassID, "ayr2");
    BOOST_CHECK_EQUAL(h2.nMintedUnits, 123456);
    BOOST_CHECK_EQUAL(h2.nLastAttestHeight, 4321);
    BOOST_CHECK_EQUAL(h2.amountLastAttestReserves, 99999999);
    BOOST_REQUIRE_EQUAL(h2.vOutReserveLock.size(), 1);
    // The migration's whole point: absent deposit leg defaults to 0.
    BOOST_CHECK_EQUAL(h2.nDepositUnits, 0);
    BOOST_CHECK_EQUAL(h2.nInsolventDepositPrincipal, 0);
    BOOST_CHECK(h2.DepositWtMaturity() == (unsigned __int128)0);
}

BOOST_AUTO_TEST_CASE(house_v5_to_v6_migration)
{
    // A pre-DR-2 (v5) record - no episode-end stamp - must still read, with
    // nDeferEndedHeight defaulting to 0 (= no episode has closed; a demanded
    // note on such a record keeps the uncapped accrual until the next recovery
    // stamps it). Same synthesis as v4->v5: a v6 record whose nDeferEndedHeight
    // is 0 ends in exactly the 4-byte v6 addendum, so dropping it + stamping
    // version 5 yields a valid v5 record.
    CHouse house;
    house.nHouseID = 12;
    house.strClassID = "ayr3";
    house.nMintedUnits = 654321;
    house.nDepositUnits = 777;                       // v5 leg must survive the round-trip
    house.nDeferCumBlocks = 42;
    // nDeferEndedHeight left at its constructor default of 0

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << house;
    std::vector<char> bytes(ss.begin(), ss.end());
    BOOST_REQUIRE_EQUAL((uint8_t)bytes[0], (uint8_t)6);
    bytes[0] = (char)5;                 // stamp as v5
    bytes.resize(bytes.size() - 4);     // drop the zeroed u32 nDeferEndedHeight

    CDataStream ssV5(bytes, SER_NETWORK, PROTOCOL_VERSION);
    CHouse h2;
    ssV5 >> h2;                         // must not throw
    BOOST_CHECK_EQUAL(h2.nHouseID, 12);
    BOOST_CHECK_EQUAL(h2.strClassID, "ayr3");
    BOOST_CHECK_EQUAL(h2.nMintedUnits, 654321);
    BOOST_CHECK_EQUAL(h2.nDepositUnits, 777);
    BOOST_CHECK_EQUAL(h2.nDeferCumBlocks, 42);
    BOOST_CHECK_EQUAL(h2.nDeferEndedHeight, 0);
}

BOOST_AUTO_TEST_CASE(house_effective_status_derivation)
{
    // The full lazy-derivation matrix (D3). Registration at height 1000:
    // deadline = 1000 + MISS_N*CADENCE; grace holds through the deadline
    // block itself, lazy stress starts at deadline + 1.
    CHouse house;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nLastAttestHeight = 1000;
    const uint32_t nDeadline = 1000 + HOUSE_ATTEST_MISS_N * HOUSE_ATTEST_CADENCE;

    // Healthy: before and AT the deadline
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 1000), HOUSE_STATUS_OPEN);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, nDeadline), HOUSE_STATUS_OPEN);

    // Missed cadence: lazily Stressed from deadline + 1, no writes
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, nDeadline + 1), HOUSE_STATUS_STRESSED);
    BOOST_CHECK_EQUAL(house.nStressSinceHeight, 0); // nothing stored

    // Window expiry: lazily Insolvent from stressOrigin + WINDOW
    const uint32_t nLazyOrigin = nDeadline + 1;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, nLazyOrigin + HOUSE_STRESSED_WINDOW - 1), HOUSE_STATUS_STRESSED);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, nLazyOrigin + HOUSE_STRESSED_WINDOW), HOUSE_STATUS_INSOLVENT);

    // Ratio-breach stress (tx-written by ATTEST): stressed immediately, even
    // while the cadence clock is fresh
    CHouse hRatio = house;
    hRatio.nLastAttestHeight = 2000;   // fresh attestation...
    hRatio.nStressSinceHeight = 2000;  // ...that showed a sub-floor ratio (T2)
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hRatio, 2000), HOUSE_STATUS_STRESSED);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hRatio, 2000 + HOUSE_STRESSED_WINDOW - 1), HOUSE_STATUS_STRESSED);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hRatio, 2000 + HOUSE_STRESSED_WINDOW), HOUSE_STATUS_INSOLVENT);

    // Earlier-origin rule: if the (derived) missed-cadence origin precedes the
    // stored ratio origin, the earlier origin drives the window clock
    CHouse hBoth = house;              // lastAttest = 1000 -> lazy origin = nDeadline+1
    hBoth.nStressSinceHeight = nLazyOrigin + 500;  // later ratio-stress record
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hBoth, nLazyOrigin + HOUSE_STRESSED_WINDOW), HOUSE_STATUS_INSOLVENT);
    // ...and a stored origin EARLIER than the lazy one wins unchanged
    CHouse hEarly = house;
    hEarly.nStressSinceHeight = 1500;  // ratio breach well before the cadence deadline
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hEarly, 1500 + HOUSE_STRESSED_WINDOW), HOUSE_STATUS_INSOLVENT);

    // Recovery shape (T4 writes done by ATTEST connect): cleared stress +
    // fresh clock derives Open again
    CHouse hRec = hRatio;
    hRec.nStressSinceHeight = 0;
    hRec.nLastAttestHeight = 2500;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hRec, 2500), HOUSE_STATUS_OPEN);

    // Stored terminal states short-circuit the derivation
    CHouse hIns = house;
    hIns.status = HOUSE_STATUS_INSOLVENT;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hIns, 1000), HOUSE_STATUS_INSOLVENT);
    CHouse hWound = house;
    hWound.status = HOUSE_STATUS_WOUNDDOWN;
    hWound.nLastAttestHeight = 0; // even with an ancient clock...
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hWound, 999999), HOUSE_STATUS_WOUNDDOWN);
}

BOOST_AUTO_TEST_CASE(house_attest_floor_logic)
{
    // HouseAttestNewStressOrigin: T2 below-floor / T4 recovery / in-band (D9).
    // rho = 10%, buffer = +5 -> recovery at 15%. Units are sats 1:1 (v1).
    CHouse house;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nLastAttestHeight = 1000;
    house.nMintedUnits = 1000000;   // N: floor = 100k sats, buffer target = 150k

    // Healthy house, healthy report (>= 15%): stays clear
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(house, 150000, 1100), 0);
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(house, 1000000, 1100), 0);

    // Below floor (< 10%): stress originates at this attest's height
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(house, 99999, 1100), 1100);
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(house, 0, 1100), 1100);

    // Exactly at the floor (10.0%) is NOT below floor - in-band, healthy stays healthy
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(house, 100000, 1100), 0);
    // Just under the buffer (14.9999%): in-band, healthy stays healthy
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(house, 149999, 1100), 0);

    // Stressed house (ratio origin 1050): in-band PRESERVES the origin...
    CHouse hStressed = house;
    hStressed.nStressSinceHeight = 1050;
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(hStressed, 120000, 1100), 1050);
    // ...below-floor keeps the ORIGINAL clock (no reset-by-re-breach)...
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(hStressed, 50000, 1100), 1050);
    // ...and only >= floor+buffer recovers
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(hStressed, 149999, 1100), 1050);
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(hStressed, 150000, 1100), 0);

    // Lazily-stressed house (missed cadence): a below-floor or in-band attest
    // MATERIALIZES the lazy origin (deadline + 1), not the attest height
    CHouse hLazy = house;
    const uint32_t nLazyOrigin = 1000 + HOUSE_ATTEST_MISS_N * HOUSE_ATTEST_CADENCE + 1;
    const int nLate = (int)nLazyOrigin + 10;
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(hLazy, 50000, nLate), nLazyOrigin);
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(hLazy, 120000, nLate), nLazyOrigin);
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(hLazy, 150000, nLate), 0);

    // Zero liabilities: any report (even 0 reserves) is a recovery - a house
    // with no notes outstanding cannot be liquidity-stressed
    CHouse hEmpty = house;
    hEmpty.nMintedUnits = 0;
    hEmpty.nStressSinceHeight = 1050;
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(hEmpty, 0, 1100), 0);
}

BOOST_AUTO_TEST_CASE(house_brassage_schedule)
{
    // 3.5 D1/D8: the redemption spread as a function of the ATTESTED ratio.
    // rho = 1000 bps, theta = 250 bps, max = 300 bps, quadratic in proximity.
    CHouse house;
    house.nMintedUnits = 1000000000;   // N = 1e9 units

    // No liabilities -> ratio is 100% by definition, no spread
    CHouse hEmpty;
    BOOST_CHECK_EQUAL(HouseAttestedRatioBps(hEmpty), 10000);
    BOOST_CHECK_EQUAL(HouseBrassageBps(hEmpty), 0);

    // At and above the floor: EXACT PAR. This is the invariant that keeps 3.4's
    // "redemption at par" promise intact for an Open house - and an Open house
    // is always here, because a below-floor attestation is precisely what makes
    // a house Stressed.
    house.amountLastAttestReserves = 100000000;   // R = 1e8 -> rr = 10.00% = rho
    BOOST_CHECK_EQUAL(HouseAttestedRatioBps(house), 1000);
    BOOST_CHECK_EQUAL(HouseBrassageBps(house), 0);
    house.amountLastAttestReserves = 500000000;   // rr = 50%
    BOOST_CHECK_EQUAL(HouseBrassageBps(house), 0);

    // At and below theta: the full spread
    house.amountLastAttestReserves = 25000000;    // rr = 2.50% = theta
    BOOST_CHECK_EQUAL(HouseAttestedRatioBps(house), 250);
    BOOST_CHECK_EQUAL(HouseBrassageBps(house), HOUSE_BRASSAGE_MAX_BPS);
    house.amountLastAttestReserves = 0;           // rr = 0
    BOOST_CHECK_EQUAL(HouseBrassageBps(house), HOUSE_BRASSAGE_MAX_BPS);

    // Between: quadratic, so it opens GENTLY just under the floor rather than
    // with a cliff (the sim's prox^2).
    house.amountLastAttestReserves = 99000000;    // rr = 9.90%, a whisker below rho
    const uint32_t nJustUnder = HouseBrassageBps(house);
    BOOST_CHECK(nJustUnder < 5);                  // ~0.05 bps - almost nothing
    house.amountLastAttestReserves = 62500000;    // rr = 6.25% - the midpoint of [theta, rho]
    BOOST_CHECK_EQUAL(HouseBrassageBps(house), HOUSE_BRASSAGE_MAX_BPS / 4);  // prox=0.5 -> prox^2=0.25

    // Monotone: the closer to theta, the steeper the exit
    uint32_t nPrev = 0;
    for (CAmount R = 100000000; R >= 25000000; R -= 5000000) {
        house.amountLastAttestReserves = R;
        const uint32_t nBps = HouseBrassageBps(house);
        BOOST_CHECK(nBps >= nPrev);
        BOOST_CHECK(nBps <= HOUSE_BRASSAGE_MAX_BPS);
        nPrev = nBps;
    }

    // The spread amount itself
    BOOST_CHECK_EQUAL(HouseBrassageAmount(1000000, 300), 30000);   // 3% of 1e6
    BOOST_CHECK_EQUAL(HouseBrassageAmount(1000000, 0), 0);
    BOOST_CHECK_EQUAL(HouseBrassageAmount(0, 300), 0);
    BOOST_CHECK_EQUAL(HouseBrassageAmount(100, 300), 3);
    BOOST_CHECK_EQUAL(HouseBrassageAmount(10, 300), 0);            // floors to nothing on dust

    // 128-bit: R*10000 overflows u64 at money-range reserves, and the spread on
    // a lambda-max supply must not wrap.
    CHouse hBig;
    hBig.nMintedUnits = (uint64_t)MAX_MONEY * 3;
    hBig.amountLastAttestReserves = MAX_MONEY;
    BOOST_CHECK_EQUAL(HouseAttestedRatioBps(hBig), 3333);          // 33.3% - above rho, no spread
    BOOST_CHECK_EQUAL(HouseBrassageBps(hBig), 0);
    BOOST_CHECK(HouseBrassageAmount((uint64_t)MAX_MONEY * 3, HOUSE_BRASSAGE_MAX_BPS) <= (CAmount)MAX_MONEY);
}

BOOST_AUTO_TEST_CASE(house_deferral_derivation)
{
    // 3.5: the option clause folds into the LAZY machine - 'd' and the
    // post-expiry 'i' are derived from the stored invocation height alone.
    CHouse house;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nLastAttestHeight = 1000;
    house.nStressSinceHeight = 1100;          // stressed by a ratio breach
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 1200), HOUSE_STATUS_STRESSED);

    // Invoking at 1200 REPLACES the ordinary stress clock with the window
    house.nDeferInvokedHeight = 1200;
    house.nDeferActivations = 1;
    house.nDeferLastActivation = 1200;
    BOOST_CHECK_EQUAL(house.DeferEndHeight(), 1200 + HOUSE_DEFER_WINDOW);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 1200), HOUSE_STATUS_DEFERRED);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 1200 + HOUSE_DEFER_WINDOW - 1), HOUSE_STATUS_DEFERRED);
    // ...and the 1008-block stress clock no longer bites while deferring: at a
    // height well past stress_since + STRESSED_WINDOW the house is still 'd'.
    BOOST_CHECK(1100 + HOUSE_STRESSED_WINDOW < 1200 + HOUSE_DEFER_WINDOW);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 1100 + HOUSE_STRESSED_WINDOW + 1), HOUSE_STATUS_DEFERRED);

    // Window expiry without recovery -> Insolvent (ARCH s7 step 6)
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 1200 + HOUSE_DEFER_WINDOW), HOUSE_STATUS_INSOLVENT);

    // One renewal buys exactly one more window
    CHouse hRenewed = house;
    hRenewed.nDeferRenewals = 1;
    BOOST_CHECK_EQUAL(hRenewed.DeferEndHeight(), 1200 + 2 * HOUSE_DEFER_WINDOW);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hRenewed, 1200 + HOUSE_DEFER_WINDOW), HOUSE_STATUS_DEFERRED);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hRenewed, 1200 + 2 * HOUSE_DEFER_WINDOW), HOUSE_STATUS_INSOLVENT);

    // Recovery (the ATTEST effect) lifts it: cleared origin + cleared invocation
    CHouse hRecovered = house;
    hRecovered.nDeferInvokedHeight = 0;
    hRecovered.nDeferRenewals = 0;
    hRecovered.nStressSinceHeight = 0;
    hRecovered.nLastAttestHeight = 1500;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hRecovered, 1500), HOUSE_STATUS_OPEN);

    // Suspended-block accounting includes the episode running right now
    BOOST_CHECK_EQUAL(house.DeferSuspendedBlocks(1500), 300);   // 1500 - 1200
    BOOST_CHECK_EQUAL(house.DeferSuspendedBlocks(1200), 0);
    CHouse hClosed = house;
    hClosed.nDeferInvokedHeight = 0;
    hClosed.nDeferCumBlocks = 300;
    BOOST_CHECK_EQUAL(hClosed.DeferSuspendedBlocks(9999), 300); // closed episode: no accrual

    // A stored terminal status still short-circuits everything
    CHouse hWound = house;
    hWound.status = HOUSE_STATUS_WOUNDDOWN;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hWound, 999999), HOUSE_STATUS_WOUNDDOWN);
}

BOOST_AUTO_TEST_CASE(house_confidence_death_guard)
{
    // D13: CD is a GUARD on invocation, not a kill switch. It never changes the
    // status - it only makes a further DEFER invalid.
    CHouse house;

    // A house that has never suspended is not confidence-dead
    BOOST_CHECK(!HouseConfidenceDead(house, 100000));

    // One activation, still inside the CD window -> a SECOND is refused
    house.nDeferActivations = 1;
    house.nDeferLastActivation = 100000;
    house.nDeferCumBlocks = 500;
    BOOST_CHECK(HouseConfidenceDead(house, 100001));
    BOOST_CHECK(HouseConfidenceDead(house, 100000 + HOUSE_CD_WINDOW_BLOCKS - 1));
    // ...but once the window has passed, the clause is available again
    BOOST_CHECK(!HouseConfidenceDead(house, 100000 + HOUSE_CD_WINDOW_BLOCKS));

    // Cumulative suspension beyond the cap is terminal for the tool regardless
    CHouse hLong;
    hLong.nDeferActivations = 1;
    hLong.nDeferLastActivation = 1;
    hLong.nDeferCumBlocks = HOUSE_CD_MAX_SUSPENDED;
    BOOST_CHECK(HouseConfidenceDead(hLong, 10000000));   // long past the CD window

    // What CD actually decides is the SECOND episode, after a recovery: a house
    // that suspended briefly and recovered may reach for the clause again once
    // the window passes; one that spent its whole suspension budget may not,
    // ever. (A house still INSIDE an episode cannot re-invoke regardless - DEFER
    // requires effective 's', and it is 'd'.)
    CHouse hJustUnder;
    hJustUnder.nDeferActivations = 1;
    hJustUnder.nDeferLastActivation = 1000;
    hJustUnder.nDeferCumBlocks = HOUSE_CD_MAX_SUSPENDED - 1;   // episode closed by recovery
    BOOST_CHECK(!HouseConfidenceDead(hJustUnder, 1000 + HOUSE_CD_WINDOW_BLOCKS));

    CHouse hAtCap = hJustUnder;
    hAtCap.nDeferCumBlocks = HOUSE_CD_MAX_SUSPENDED;
    BOOST_CHECK(HouseConfidenceDead(hAtCap, 1000 + HOUSE_CD_WINDOW_BLOCKS));
    BOOST_CHECK(HouseConfidenceDead(hAtCap, 10000000));        // and permanently

    // The running episode is counted, so the budget cannot be evaded by simply
    // never closing the suspension.
    CHouse hRunning;
    hRunning.nDeferActivations = 1;
    hRunning.nDeferLastActivation = 1000;
    hRunning.nDeferInvokedHeight = 1000;
    BOOST_CHECK_EQUAL(hRunning.DeferSuspendedBlocks(1000 + HOUSE_CD_MAX_SUSPENDED),
                      HOUSE_CD_MAX_SUSPENDED);
    BOOST_CHECK(HouseConfidenceDead(hRunning, 1000 + HOUSE_CD_MAX_SUSPENDED));
}

BOOST_AUTO_TEST_CASE(house_mint_caps_rho_at_mint)
{
    // 3.5 D2: the binding mint cap is min(capital lambda*E, reserve R/rho).
    CHouse house;
    house.nTier = HOUSE_TIER_MULTI_PARTNER;   // lambda = 3.0
    HousePartner p;
    p.vchPubKey = std::vector<unsigned char>(33, 0x02);
    p.amountPledge = 100000000;               // 1 BTX escrow
    p.status = HOUSE_PARTNER_ACTIVE;
    house.vPartner.push_back(p);

    // Capital cap = 3 * 1e8 = 3e8 units, independent of reserves
    BOOST_CHECK_EQUAL(HouseCapitalCapUnits(house), 300000000);

    // A house that has NEVER attested carries R = 0: reserve cap 0, so the
    // binding cap is 0 - it must attest before it can mint anything.
    BOOST_CHECK_EQUAL(house.amountLastAttestReserves, 0);
    BOOST_CHECK_EQUAL(HouseReserveCapUnits(house), 0);
    BOOST_CHECK_EQUAL(HouseMintCapUnits(house), 0);

    // rho = 10%: an attested till of R supports R/rho = 10*R units
    house.amountLastAttestReserves = 10000000;         // 0.1 BTX
    BOOST_CHECK_EQUAL(HouseReserveCapUnits(house), 100000000);   // 1e8
    BOOST_CHECK_EQUAL(HouseMintCapUnits(house), 100000000);      // RESERVE binds

    // Enough till to out-run the capital cap -> capital binds again
    house.amountLastAttestReserves = 50000000;         // 0.5 BTX -> 5e8 units
    BOOST_CHECK_EQUAL(HouseReserveCapUnits(house), 500000000);
    BOOST_CHECK_EQUAL(HouseMintCapUnits(house), 300000000);      // CAPITAL binds

    // Exactly at the crossover both agree
    house.amountLastAttestReserves = 30000000;         // 0.3 BTX -> 3e8 units
    BOOST_CHECK_EQUAL(HouseReserveCapUnits(house), HouseCapitalCapUnits(house));
    BOOST_CHECK_EQUAL(HouseMintCapUnits(house), 300000000);

    // The pre-3.5 hole this closes: escrow alone no longer authorizes issuance.
    // Top up escrow 10x with an unchanged till - the capital cap explodes, the
    // BINDING cap does not move.
    house.vPartner[0].amountPledge = 1000000000;       // 10 BTX
    BOOST_CHECK_EQUAL(HouseCapitalCapUnits(house), 3000000000);
    BOOST_CHECK_EQUAL(HouseMintCapUnits(house), 300000000);      // still the till

    // Money-range operands do not overflow u64 (R*100 = 2.1e17)
    CHouse hMax;
    hMax.amountLastAttestReserves = MAX_MONEY;
    BOOST_CHECK_EQUAL(HouseReserveCapUnits(hMax), (uint64_t)MAX_MONEY * 10);
}

BOOST_AUTO_TEST_CASE(house_attest_hash_helpers)
{
    // Challenge binds house, height, block hash, and outpoint independently
    const uint256 houseA = uint256S("aa"), houseB = uint256S("bb");
    const uint256 blockA = uint256S("c1"), blockB = uint256S("c2");
    const COutPoint outA(uint256S("d1"), 0), outB(uint256S("d1"), 1);

    const uint256 base = HouseAttestChallenge(houseA, 100, blockA, outA);
    BOOST_CHECK(base == HouseAttestChallenge(houseA, 100, blockA, outA));    // deterministic
    BOOST_CHECK(base != HouseAttestChallenge(houseB, 100, blockA, outA));    // cross-house
    BOOST_CHECK(base != HouseAttestChallenge(houseA, 101, blockA, outA));    // height
    BOOST_CHECK(base != HouseAttestChallenge(houseA, 100, blockB, outA));    // reorg
    BOOST_CHECK(base != HouseAttestChallenge(houseA, 100, blockA, outB));    // outpoint

    // Proof-set hash covers outpoints + pubkeys, NOT signatures
    AttestProof p1;
    p1.outpoint = outA;
    p1.vchPubKey = std::vector<unsigned char>(33, 0x02);
    p1.vchSig = std::vector<unsigned char>(70, 0x30);
    AttestProof p2 = p1;
    p2.vchSig = std::vector<unsigned char>(70, 0x31);                        // different sig
    BOOST_CHECK(HouseAttestProofSetHash({p1}) == HouseAttestProofSetHash({p2}));
    AttestProof p3 = p1;
    p3.outpoint = outB;
    BOOST_CHECK(HouseAttestProofSetHash({p1}) != HouseAttestProofSetHash({p3}));
    BOOST_CHECK(HouseAttestProofSetHash({p1, p3}) != HouseAttestProofSetHash({p3, p1})); // order-bound

    // Approver sighash binds every field
    const uint256 ps = HouseAttestProofSetHash({p1});
    const uint256 ho = uint256S("ee");
    const uint256 sh = HouseAttestSigHash(houseA, 100, 5000, ps, ho);
    BOOST_CHECK(sh != HouseAttestSigHash(houseB, 100, 5000, ps, ho));
    BOOST_CHECK(sh != HouseAttestSigHash(houseA, 101, 5000, ps, ho));
    BOOST_CHECK(sh != HouseAttestSigHash(houseA, 100, 5001, ps, ho));
    BOOST_CHECK(sh != HouseAttestSigHash(houseA, 100, 5000, HouseAttestProofSetHash({p3}), ho));
    BOOST_CHECK(sh != HouseAttestSigHash(houseA, 100, 5000, ps, uint256S("ef")));
}

// Build a shape-valid ATTEST tx around the given payload
static CMutableTransaction MakeAttestTx(const HouseAttest& att)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_ATTEST;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << att;
    mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));   // fee funding
    mtx.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));   // change
    return mtx;
}

BOOST_AUTO_TEST_CASE(house_attest_shape)
{
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();

    HouseAttest att;
    att.nHouseID = 1;
    att.nSchemaVersion = 1;
    att.nAsOfHeight = 100;
    att.amountReserves = 50000;
    AttestProof proof;
    proof.outpoint = COutPoint(uint256S("d1"), 0);
    proof.vchPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
    proof.vchSig = std::vector<unsigned char>(70, 0x30);
    att.vProofs.push_back(proof);
    att.vApproverIndex.push_back(0);
    att.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));

    CValidationState state;
    BOOST_CHECK(CheckHouseTransactionShape(CTransaction(MakeAttestTx(att)), state));

    // Wrong schema version
    {
        HouseAttest bad = att;
        bad.nSchemaVersion = 2;
        CValidationState s;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad)), s));
    }
    // Duplicate proof outpoint (would double-count the coin)
    {
        HouseAttest bad = att;
        bad.vProofs.push_back(proof);
        CValidationState s;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad)), s));
    }
    // Positive claim with no proofs / zero claim with proofs
    {
        HouseAttest bad = att;
        bad.vProofs.clear();
        CValidationState s;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad)), s));
        HouseAttest bad2 = att;
        bad2.amountReserves = 0;
        CValidationState s2;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad2)), s2));
    }
    // Zero-reserve, zero-proof attestation is a VALID honest report
    {
        HouseAttest zero = att;
        zero.amountReserves = 0;
        zero.vProofs.clear();
        CValidationState s;
        BOOST_CHECK(CheckHouseTransactionShape(CTransaction(MakeAttestTx(zero)), s));
    }
    // Null outpoint / bad pubkey size / oversized sig / no approvers
    {
        HouseAttest bad = att;
        bad.vProofs[0].outpoint.SetNull();
        CValidationState s;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad)), s));
        HouseAttest bad2 = att;
        bad2.vProofs[0].vchPubKey = std::vector<unsigned char>(20, 0x02);
        CValidationState s2;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad2)), s2));
        HouseAttest bad3 = att;
        bad3.vProofs[0].vchSig = std::vector<unsigned char>(81, 0x30);
        CValidationState s3;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad3)), s3));
        HouseAttest bad4 = att;
        bad4.vApproverIndex.clear();
        bad4.vApproverSig.clear();
        CValidationState s4;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad4)), s4));
    }
    // Too many proofs
    {
        HouseAttest bad = att;
        bad.vProofs.clear();
        for (size_t i = 0; i <= MAX_ATTEST_PROOFS; i++) {
            AttestProof p = proof;
            p.outpoint = COutPoint(uint256S("d1"), (uint32_t)i);
            bad.vProofs.push_back(p);
        }
        CValidationState s;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad)), s));
    }
    // Negative / oversized reserve claim
    {
        HouseAttest bad = att;
        bad.amountReserves = -1;
        CValidationState s;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad)), s));
    }
}

// ---------------------------------------------------------------------------
// R-i6: the NEGATIVE direction of the 3.5 house-op consensus guards.
//
// Before this, no test invoked CheckHouseOperation at all - the guards were
// reachable only through the wallet, which fail-fasts on the same conditions and
// so never builds a rejectable tx. Deleting a guard left the whole suite green.
// Each case below drives the contextual check directly and asserts the EXACT
// reject reason, so a fixture that trips an earlier guard is caught rather than
// passing for the wrong reason. Every reason asserted here fires BEFORE any
// ECDSA in its branch, so a placeholder approver/reclaim signature suffices.
// ---------------------------------------------------------------------------

namespace {
static bool GuardNoHash(const uint256&) { return false; }
static bool GuardNoClass(const std::string&) { return false; }
static bool GuardNoBlock(uint32_t, uint256&) { return false; }

// An effectively-OPEN multi-partner house: fresh attestation, ample reserves,
// no stress, not deferring. Partner 0 ACTIVE, partner 1 TAIL and past unlock.
static CHouse MakeGuardHouse()
{
    CHouse house;
    house.nHouseID = 7;
    house.houseID = uint256S("f00d");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 1;
    house.strClassID = "guard";
    house.nDenomMgGold = 1000;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nLastAttestHeight = 1000;
    house.amountLastAttestReserves = 100 * COIN;

    HousePartner p0;
    p0.vchPubKey = std::vector<unsigned char>(33, 0x02);
    p0.amountPledge = HOUSE_MIN_PLEDGE;
    p0.vOutPledge.push_back(COutPoint(uint256S("a0"), 0));
    p0.status = HOUSE_PARTNER_ACTIVE;

    HousePartner p1 = p0;
    p1.vOutPledge.clear();
    p1.vOutPledge.push_back(COutPoint(uint256S("a1"), 0));
    p1.status = HOUSE_PARTNER_TAIL;
    p1.nTailUnlockHeight = 900;

    house.vPartner.push_back(p0);
    house.vPartner.push_back(p1);
    return house;
}

// A house-escrow coin (fHouseEscrow, this house) at value v.
static Coin GuardEscrowCoin(uint32_t nHouseID, CAmount v)
{
    Coin coin(CTxOut(v, HouseEscrowScript(uint256S("f00d"))), 1000, false, false, false, 0);
    coin.SetHouseEscrow(nHouseID);
    return coin;
}

static CMutableTransaction MakeReclaimTx(uint32_t nHouseID, uint32_t nPartnerIdx, const COutPoint& spend)
{
    HouseReclaim rec;
    rec.nHouseID = nHouseID;
    rec.nPartnerIndex = nPartnerIdx;
    rec.vchSig = std::vector<unsigned char>(70, 0x30);
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_RECLAIM;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << rec;
    mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    mtx.vin.push_back(CTxIn(spend));
    mtx.vout.push_back(CTxOut(1 * COIN, GetScriptForDestination(CKeyID())));
    return mtx;
}

static CMutableTransaction MakeHouseOpTx(uint8_t nOp, const CDataStream& payload)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = nOp;
    mtx.vchHousePayload = std::vector<unsigned char>(payload.begin(), payload.end());
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
    mtx.vout.push_back(CTxOut(1 * COIN, GetScriptForDestination(CKeyID())));
    return mtx;
}
} // namespace

BOOST_AUTO_TEST_CASE(house_reclaim_cannot_steal_escrow)
{
    // R-i6 CRITICAL regression: a tail partner must NOT spend the DEFER till or
    // the brassage pot (house-escrow coins in NO partner's pledge). The guard
    // fires before the D13 cap and the approver signature.
    CHouse house = MakeGuardHouse();
    const int nHeight = 1000;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, nHeight), HOUSE_STATUS_OPEN);

    const COutPoint tillOut(uint256S("dead"), 0);
    house.vOutReserveLock.push_back(tillOut);
    Coin till = GuardEscrowCoin(house.nHouseID, 50 * COIN);

    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
    auto fnGetCoin = [&](const COutPoint& o, Coin& c) {
        if (o == tillOut) { c = till; return true; }
        if (o == COutPoint(uint256S("a1"), 0)) { c = GuardEscrowCoin(house.nHouseID, HOUSE_MIN_PLEDGE); return true; }
        return false;
    };

    // Partner 1 (TAIL, unlocked) tries to reclaim the till -> theft rejected.
    {
        CMutableTransaction mtx = MakeReclaimTx(house.nHouseID, 1, tillOut);
        CValidationState state; CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, nHeight, fnGetHouse, GuardNoHash, GuardNoClass, fnGetCoin, GuardNoBlock, houseOut));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-reclaim-not-own-pledge");
    }
    // Control: reclaiming its OWN pledge coin (a1) passes the ownership guard and
    // only then fails on the placeholder signature - proving no over-rejection.
    {
        CMutableTransaction mtx = MakeReclaimTx(house.nHouseID, 1, COutPoint(uint256S("a1"), 0));
        CValidationState state; CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, nHeight, fnGetHouse, GuardNoHash, GuardNoClass, fnGetCoin, GuardNoBlock, houseOut));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-reclaim-sig");
    }
}

BOOST_AUTO_TEST_CASE(house_op_status_guards)
{
    auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };

    // DEFER is a Stressed-only tool: an Open house is refused (expropriation bar).
    {
        CHouse house = MakeGuardHouse();               // Open
        HouseDefer def; def.nHouseID = house.nHouseID; def.nPrevLastActivation = 0;
        def.vApproverIndex.push_back(0); def.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << def;
        CMutableTransaction mtx = MakeHouseOpTx(HOUSE_OP_DEFER, ss);
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
        CValidationState state; CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, 1000, fnGetHouse, GuardNoHash, GuardNoClass, fnNoCoin, GuardNoBlock, houseOut));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-defer-not-stressed");
    }
    // DEFER by a confidence-dead (Stressed) house is refused before the sig.
    {
        CHouse house = MakeGuardHouse();
        house.nLastAttestHeight = 2000; house.nStressSinceHeight = 2000; // Stressed at 2000
        house.nDeferCumBlocks = HOUSE_CD_MAX_SUSPENDED;                  // credibility spent
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 2000), HOUSE_STATUS_STRESSED);
        HouseDefer def; def.nHouseID = house.nHouseID; def.nPrevLastActivation = 0;
        def.vApproverIndex.push_back(0); def.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << def;
        CMutableTransaction mtx = MakeHouseOpTx(HOUSE_OP_DEFER, ss);
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
        CValidationState state; CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, 2000, fnGetHouse, GuardNoHash, GuardNoClass, fnNoCoin, GuardNoBlock, houseOut));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-defer-confidence-dead");
    }
    // RELEASE is refused while the house is not effectively Open (till stays put).
    {
        CHouse house = MakeGuardHouse();
        house.nLastAttestHeight = 2000; house.nStressSinceHeight = 2000; // Stressed
        HouseRelease rel; rel.nHouseID = house.nHouseID;
        rel.vApproverIndex.push_back(0); rel.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << rel;
        CMutableTransaction mtx = MakeHouseOpTx(HOUSE_OP_RELEASE, ss);
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
        CValidationState state; CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, 2000, fnGetHouse, GuardNoHash, GuardNoClass, fnNoCoin, GuardNoBlock, houseOut));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-release-not-open");
    }
    // RECLAIM is refused while the house is Stressed/Deferred - no pledge walks
    // out during the window - and this fires for a TAIL, unlock-passed partner
    // that would otherwise be eligible (the integration gate only ever presented
    // an ACTIVE partner, which trips the not-tail guard instead: R-i6 finding).
    {
        CHouse house = MakeGuardHouse();
        house.nLastAttestHeight = 2000; house.nStressSinceHeight = 2000; // Stressed
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 2000), HOUSE_STATUS_STRESSED);
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
        CMutableTransaction mtx = MakeReclaimTx(house.nHouseID, 1, COutPoint(uint256S("a1"), 0));
        CValidationState state; CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, 2000, fnGetHouse, GuardNoHash, GuardNoClass, fnNoCoin, GuardNoBlock, houseOut));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-reclaim-stressed");
    }

    // RENEW is refused when the house is not deferring...
    {
        CHouse house = MakeGuardHouse();               // Open
        HouseRenew ren; ren.nHouseID = house.nHouseID;
        ren.vApproverIndex.push_back(0); ren.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << ren;
        CMutableTransaction mtx = MakeHouseOpTx(HOUSE_OP_RENEW, ss);
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
        CValidationState state; CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, 1000, fnGetHouse, GuardNoHash, GuardNoClass, fnNoCoin, GuardNoBlock, houseOut));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-renew-not-deferred");
    }
    // ...and refused when the one permitted renewal is already spent.
    {
        CHouse house = MakeGuardHouse();
        house.nDeferInvokedHeight = 1500; house.nDeferRenewals = HOUSE_DEFER_MAX_RENEWALS;
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 1600), HOUSE_STATUS_DEFERRED);
        HouseRenew ren; ren.nHouseID = house.nHouseID;
        ren.vApproverIndex.push_back(0); ren.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << ren;
        CMutableTransaction mtx = MakeHouseOpTx(HOUSE_OP_RENEW, ss);
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
        CValidationState state; CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, 1600, fnGetHouse, GuardNoHash, GuardNoClass, fnNoCoin, GuardNoBlock, houseOut));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-renew-exhausted");
    }
}

BOOST_AUTO_TEST_CASE(house_release_renew_sighash_prevouts_binding)
{
    // R-i6 replay fix: RELEASE/RENEW approvals must bind the tx prevouts, so an
    // approval published in one deferral episode cannot be replayed against a
    // fresh till in a later one (the till coins are OP_TRUE - the approver sig is
    // their sole authorization).
    const uint256 id = uint256S("ab");
    const uint256 outs = uint256S("cd");
    const uint256 pvA = uint256S("11");
    const uint256 pvB = uint256S("22");

    BOOST_CHECK(HouseReleaseSigHash(id, pvA, outs) == HouseReleaseSigHash(id, pvA, outs));
    BOOST_CHECK(HouseReleaseSigHash(id, pvA, outs) != HouseReleaseSigHash(id, pvB, outs));

    // RENEW's index resets to 0 every episode, so the prevouts are what
    // distinguish one episode's approval from a later one's.
    BOOST_CHECK(HouseRenewSigHash(id, 0, pvA, outs) != HouseRenewSigHash(id, 0, pvB, outs));
    // Domain separation between the two ops holds too.
    BOOST_CHECK(HouseReleaseSigHash(id, pvA, outs) != HouseRenewSigHash(id, 0, pvA, outs));
}

BOOST_AUTO_TEST_SUITE_END()
