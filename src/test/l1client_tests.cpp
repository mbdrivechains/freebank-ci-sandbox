// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <l1client.h>

#include <primitives/transaction.h>
#include <test/test_bitcoin.h>
#include <uint256.h>
#include <univalue.h>
#include <utilstrencodings.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

// The canned JSON in this suite is captured from a live bip300301_enforcer
// v0.3.4 ValidatorService via grpcurl (bench, 2026-07-08). If the enforcer
// wire format changes these fixtures must be re-captured, not hand-edited.

BOOST_FIXTURE_TEST_SUITE(l1client_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(l1client_transport_values)
{
    BOOST_CHECK(IsValidL1Transport("jsonrpc"));
    BOOST_CHECK(IsValidL1Transport("enforcer"));
    BOOST_CHECK(!IsValidL1Transport(""));
    BOOST_CHECK(!IsValidL1Transport("grpc"));
    BOOST_CHECK(!IsValidL1Transport("Enforcer"));
}

BOOST_AUTO_TEST_CASE(l1client_consensus_hex)
{
    // uint256's string form is display order (byte-reversed); ConsensusHex is
    // internal order. Value 1 = internal bytes 01 00 ... 00.
    uint256 one = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
    BOOST_CHECK_EQUAL(ConsensusHexFromUint256(one),
        "0100000000000000000000000000000000000000000000000000000000000000");
    BOOST_CHECK(Uint256FromConsensusHex("0100000000000000000000000000000000000000000000000000000000000000") == one);

    // Round trip an asymmetric value
    uint256 hash = uint256S("412df67dca755f78c3c05aaece866329490fb446340d4628ab94a3d860ccc569");
    BOOST_CHECK(Uint256FromConsensusHex(ConsensusHexFromUint256(hash)) == hash);

    // Bad input -> null
    BOOST_CHECK(Uint256FromConsensusHex("").IsNull());
    BOOST_CHECK(Uint256FromConsensusHex("abcd").IsNull());
    BOOST_CHECK(Uint256FromConsensusHex("zz00000000000000000000000000000000000000000000000000000000000000").IsNull());
}

BOOST_AUTO_TEST_CASE(l1client_parse_chaintip)
{
    // Live GetChainTip response. ReverseHex hashes equal bitcoin display hex
    // (verified against getbestblockhash); uint64 timestamp arrives as a
    // JSON string.
    UniValue response(UniValue::VOBJ);
    BOOST_REQUIRE(response.read(
        "{\"blockHeaderInfo\": {"
        "\"blockHash\": {\"hex\": \"412df67dca755f78c3c05aaece866329490fb446340d4628ab94a3d860ccc569\"},"
        "\"prevBlockHash\": {\"hex\": \"4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8\"},"
        "\"height\": 3,"
        "\"work\": {\"hex\": \"0200000000000000000000000000000000000000000000000000000000000000\"},"
        "\"timestamp\": \"1783480879\"}}"));

    L1BlockHeader header;
    BOOST_REQUIRE(ParseEnforcerChainTip(response, header));
    BOOST_CHECK(header.hashBlock == uint256S("412df67dca755f78c3c05aaece866329490fb446340d4628ab94a3d860ccc569"));
    BOOST_CHECK(header.hashPrevBlock == uint256S("4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8"));
    BOOST_CHECK_EQUAL(header.nHeight, 3);
    BOOST_CHECK_EQUAL(header.nTime, 1783480879);

    // Missing blockHash -> parse failure
    UniValue bad(UniValue::VOBJ);
    BOOST_REQUIRE(bad.read("{\"blockHeaderInfo\": {\"height\": 3}}"));
    BOOST_CHECK(!ParseEnforcerChainTip(bad, header));
}

BOOST_AUTO_TEST_CASE(l1client_parse_headerinfos)
{
    // GetBlockHeaderInfo with ancestors, newest first. The genesis entry has
    // proto3 zero defaults omitted (no height key).
    UniValue response(UniValue::VOBJ);
    BOOST_REQUIRE(response.read(
        "{\"headerInfos\": ["
        "{\"blockHash\": {\"hex\": \"4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8\"},"
        "\"prevBlockHash\": {\"hex\": \"6635079af4e71b8e1de215be1ae0ab44def0157506e6226b681ce889d319f740\"},"
        "\"height\": 2, \"timestamp\": \"1783480879\"},"
        "{\"blockHash\": {\"hex\": \"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206\"},"
        "\"timestamp\": \"1296688602\"}"
        "]}"));

    std::vector<L1BlockHeader> vHeader;
    BOOST_REQUIRE(ParseEnforcerHeaderInfos(response, vHeader));
    BOOST_REQUIRE_EQUAL(vHeader.size(), 2);
    BOOST_CHECK_EQUAL(vHeader[0].nHeight, 2);
    BOOST_CHECK(vHeader[0].hashBlock == uint256S("4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8"));
    BOOST_CHECK_EQUAL(vHeader[1].nHeight, 0);
    BOOST_CHECK(vHeader[1].hashPrevBlock.IsNull());

    // Empty list -> failure (caller always requests at least the block itself)
    UniValue empty(UniValue::VOBJ);
    BOOST_REQUIRE(empty.read("{\"headerInfos\": []}"));
    BOOST_CHECK(!ParseEnforcerHeaderInfos(empty, vHeader));
}

BOOST_AUTO_TEST_CASE(l1client_parse_bmm_commitment)
{
    bool fBlockFound;
    bool fHaveCommitment;
    uint256 hashCommitment;

    // Unknown block
    UniValue notFound(UniValue::VOBJ);
    BOOST_REQUIRE(notFound.read(
        "{\"blockNotFound\": {\"blockHash\": {\"hex\": \"412df67dca755f78c3c05aaece866329490fb446340d4628ab94a3d860ccc569\"}}}"));
    BOOST_REQUIRE(ParseEnforcerBmmCommitment(notFound, fBlockFound, fHaveCommitment, hashCommitment));
    BOOST_CHECK(!fBlockFound);
    BOOST_CHECK(!fHaveCommitment);

    // Known block, no h* for this sidechain (live capture)
    UniValue noCommit(UniValue::VOBJ);
    BOOST_REQUIRE(noCommit.read("{\"commitment\": {}}"));
    BOOST_REQUIRE(ParseEnforcerBmmCommitment(noCommit, fBlockFound, fHaveCommitment, hashCommitment));
    BOOST_CHECK(fBlockFound);
    BOOST_CHECK(!fHaveCommitment);

    // Known block with a commitment. bmm_commitment is ConsensusHex
    // (internal byte order): the reverse of the display-order h*.
    uint256 hashBMM = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
    UniValue commit(UniValue::VOBJ);
    BOOST_REQUIRE(commit.read(
        "{\"commitment\": {\"commitment\": {\"hex\": \"0100000000000000000000000000000000000000000000000000000000000000\"}}}"));
    BOOST_REQUIRE(ParseEnforcerBmmCommitment(commit, fBlockFound, fHaveCommitment, hashCommitment));
    BOOST_CHECK(fBlockFound);
    BOOST_CHECK(fHaveCommitment);
    BOOST_CHECK(hashCommitment == hashBMM);

    // Garbage -> parse failure
    UniValue garbage(UniValue::VOBJ);
    BOOST_REQUIRE(garbage.read("{\"unexpected\": 1}"));
    BOOST_CHECK(!ParseEnforcerBmmCommitment(garbage, fBlockFound, fHaveCommitment, hashCommitment));
}

BOOST_AUTO_TEST_CASE(l1client_parse_block_deposit_txids)
{
    // GetBlockInfo response: one deposit event and one withdrawal event; only
    // the deposit txid (ReverseHex = display order) should be collected.
    UniValue response(UniValue::VOBJ);
    BOOST_REQUIRE(response.read(
        "{\"infos\": [{"
        "\"headerInfo\": {\"blockHash\": {\"hex\": \"412df67dca755f78c3c05aaece866329490fb446340d4628ab94a3d860ccc569\"}, \"height\": 3},"
        "\"blockInfo\": {\"events\": ["
        "{\"deposit\": {\"sequenceNumber\": \"7\","
        "\"outpoint\": {\"txid\": {\"hex\": \"4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8\"}, \"vout\": 1},"
        "\"output\": {\"address\": {\"hex\": \"deadbeef\"}, \"valueSats\": \"1000000000\"}}},"
        "{\"withdrawalBundle\": {\"m6id\": {\"hex\": \"6635079af4e71b8e1de215be1ae0ab44def0157506e6226b681ce889d319f740\"}, \"event\": {\"failed\": {}}}}"
        "]}}]}"));

    std::vector<uint256> vTxid;
    BOOST_REQUIRE(ParseEnforcerBlockDepositTxids(response, vTxid));
    BOOST_REQUIRE_EQUAL(vTxid.size(), 1);
    BOOST_CHECK(vTxid[0] == uint256S("4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8"));

    // Block found, no events for this sidechain
    UniValue noEvents(UniValue::VOBJ);
    BOOST_REQUIRE(noEvents.read(
        "{\"infos\": [{\"headerInfo\": {\"blockHash\": {\"hex\": \"412df67dca755f78c3c05aaece866329490fb446340d4628ab94a3d860ccc569\"}, \"height\": 3}, \"blockInfo\": {}}]}"));
    BOOST_REQUIRE(ParseEnforcerBlockDepositTxids(noEvents, vTxid));
    BOOST_CHECK(vTxid.empty());

    // Unknown block -> empty infos -> failure
    UniValue unknown(UniValue::VOBJ);
    BOOST_REQUIRE(unknown.read("{\"infos\": []}"));
    BOOST_CHECK(!ParseEnforcerBlockDepositTxids(unknown, vTxid));
}

BOOST_AUTO_TEST_CASE(l1client_parse_ctip)
{
    uint256 txid;
    uint32_t n = 999;

    UniValue response(UniValue::VOBJ);
    BOOST_REQUIRE(response.read(
        "{\"ctip\": {\"txid\": {\"hex\": \"4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8\"},"
        "\"vout\": 2, \"value\": \"1000000000\", \"sequenceNumber\": \"5\"}}"));
    BOOST_REQUIRE(ParseEnforcerCtip(response, txid, n));
    BOOST_CHECK(txid == uint256S("4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8"));
    BOOST_CHECK_EQUAL(n, 2);

    // Absent vout = proto3 zero default
    UniValue voutZero(UniValue::VOBJ);
    BOOST_REQUIRE(voutZero.read(
        "{\"ctip\": {\"txid\": {\"hex\": \"4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8\"}, \"value\": \"1000000000\"}}"));
    BOOST_REQUIRE(ParseEnforcerCtip(voutZero, txid, n));
    BOOST_CHECK_EQUAL(n, 0);

    // No ctip (no deposits yet) -> false
    UniValue noCtip(UniValue::VOBJ);
    BOOST_REQUIRE(noCtip.read("{}"));
    BOOST_CHECK(!ParseEnforcerCtip(noCtip, txid, n));
}

BOOST_AUTO_TEST_CASE(l1client_parse_withdrawal_events)
{
    // GetTwoWayPegData with withdrawal_bundle events across two blocks: one
    // Succeeded, one Failed, one Submitted. m6id is ConsensusHex (internal byte
    // order) -> decodes byte-reversed relative to display, like bmm_commitment.
    // m6id 0100..00 (internal) == uint256 value 1 (display ..0001).
    UniValue response(UniValue::VOBJ);
    BOOST_REQUIRE(response.read(
        "{\"blocks\": ["
        "{\"blockHeaderInfo\": {\"blockHash\": {\"hex\": \"00000000000000000000000000000000000000000000000000000000000000aa\"}},"
        "\"blockInfo\": {\"events\": ["
        "{\"withdrawalBundle\": {\"m6id\": {\"hex\": \"0100000000000000000000000000000000000000000000000000000000000000\"},"
        "\"event\": {\"succeeded\": {\"sequenceNumber\": \"3\", \"transaction\": {\"hex\": \"abcd\"}}}}},"
        "{\"deposit\": {\"sequenceNumber\": \"4\"}}"
        "]}},"
        "{\"blockInfo\": {\"events\": ["
        "{\"withdrawalBundle\": {\"m6id\": {\"hex\": \"0200000000000000000000000000000000000000000000000000000000000000\"},"
        "\"event\": {\"failed\": {}}}},"
        "{\"withdrawalBundle\": {\"m6id\": {\"hex\": \"0300000000000000000000000000000000000000000000000000000000000000\"},"
        "\"event\": {\"submitted\": {}}}}"
        "]}}"
        "]}"));

    std::vector<L1WithdrawalEvent> vEvents;
    BOOST_REQUIRE(ParseEnforcerWithdrawalEvents(response, vEvents));
    BOOST_REQUIRE_EQUAL(vEvents.size(), 3);   // deposit event ignored

    BOOST_CHECK(vEvents[0].m6id == uint256S("0000000000000000000000000000000000000000000000000000000000000001"));
    BOOST_CHECK_EQUAL(vEvents[0].status, 'S');
    // Block hash is ReverseHex (display order) - no byte flip
    BOOST_CHECK(vEvents[0].hashMainBlock == uint256S("00000000000000000000000000000000000000000000000000000000000000aa"));
    // Second fixture block has no blockHeaderInfo: events still parse, hash null
    BOOST_CHECK(vEvents[1].hashMainBlock.IsNull());
    BOOST_CHECK(vEvents[1].m6id == uint256S("0000000000000000000000000000000000000000000000000000000000000002"));
    BOOST_CHECK_EQUAL(vEvents[1].status, 'F');
    BOOST_CHECK(vEvents[2].m6id == uint256S("0000000000000000000000000000000000000000000000000000000000000003"));
    BOOST_CHECK_EQUAL(vEvents[2].status, 'U');

    // Empty / no peg data -> valid empty result
    UniValue empty(UniValue::VOBJ);
    BOOST_REQUIRE(empty.read("{\"blocks\": []}"));
    BOOST_CHECK(ParseEnforcerWithdrawalEvents(empty, vEvents));
    BOOST_CHECK(vEvents.empty());
}

BOOST_AUTO_TEST_CASE(l1client_cusf_fee_codec)
{
    // The enforcer's BlindedM6 fee output is exactly OP_RETURN PUSH8(fee) in
    // BIG-endian byte order (bip300301_enforcer lib/types.rs). 1,000,000 sats
    // = 0x00000000000f4240 big-endian.
    CScript script = EncodeWithdrawalFeesCUSF(1000000);
    BOOST_CHECK_EQUAL(HexStr(script.begin(), script.end()), "6a0800000000000f4240");

    CAmount amount = 0;
    BOOST_REQUIRE(DecodeWithdrawalFeesCUSF(script, amount));
    BOOST_CHECK_EQUAL(amount, 1000000);

    // Round-trip assorted values incl. 0 and MAX_MONEY
    for (const CAmount test : {CAmount(0), CAmount(1), CAmount(546), CAmount(MAX_MONEY)}) {
        CAmount out = -1;
        BOOST_REQUIRE(DecodeWithdrawalFeesCUSF(EncodeWithdrawalFeesCUSF(test), out));
        BOOST_CHECK_EQUAL(out, test);
    }

    // The legacy (little-endian CDataStream) encoding of the same value must
    // NOT decode as CUSF - byte order differs - and vice versa sizes match, so
    // this guards against silently accepting the wrong endianness.
    CScript scriptLegacy = EncodeWithdrawalFees(1000000);
    CAmount cross = 0;
    if (DecodeWithdrawalFeesCUSF(scriptLegacy, cross))
        BOOST_CHECK(cross != 1000000);

    // Over-MAX_MONEY big-endian value is rejected
    CScript bad;
    bad << OP_RETURN;
    bad << std::vector<unsigned char>{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    BOOST_CHECK(!DecodeWithdrawalFeesCUSF(bad, cross));

    // Wrong shapes rejected
    BOOST_CHECK(!DecodeWithdrawalFeesCUSF(CScript(), cross));
    BOOST_CHECK(!DecodeWithdrawalFeesCUSF(CScript() << OP_RETURN, cross));
    BOOST_CHECK(!DecodeWithdrawalFeesCUSF(CScript() << OP_RETURN << std::vector<unsigned char>{0x01}, cross));
}

BOOST_AUTO_TEST_CASE(l1client_blinded_m6id)
{
    // The enforcer m6id is the txid of the bundle with inputs stripped. Verify
    // the txid actually changes when the dummy input is removed and that the
    // zero-input txid is stable (it is what BroadcastWithdrawalBundle sends).
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1); // chassis dummy input (null prevout)
    mtx.vin[0].scriptSig = CScript() << OP_0;
    mtx.vout.push_back(CTxOut(0, EncodeWithdrawalFeesCUSF(1000000)));
    mtx.vout.push_back(CTxOut(100000000, CScript() << OP_DUP << OP_HASH160
        << std::vector<unsigned char>(20, 0x11) << OP_EQUALVERIFY << OP_CHECKSIG));

    const uint256 hashBundle = CTransaction(mtx).GetHash();

    CMutableTransaction mtxBlind(mtx);
    mtxBlind.vin.clear();
    const uint256 m6id = CTransaction(mtxBlind).GetHash();

    BOOST_CHECK(hashBundle != m6id);
    BOOST_CHECK(!m6id.IsNull());
    // Deterministic: stripping again yields the same m6id
    BOOST_CHECK(CTransaction(mtxBlind).GetHash() == m6id);
}

BOOST_AUTO_TEST_SUITE_END()
