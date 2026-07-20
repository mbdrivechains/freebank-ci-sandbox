// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bill.h>

#include <consensus/validation.h>
#include <key.h>
#include <script/standard.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <utilstrencodings.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bill_tests, BasicTestingSetup)

static std::vector<unsigned char> TestBody()
{
    const std::string str = "test-bill-encrypted-body";
    return std::vector<unsigned char>(str.begin(), str.end());
}

static const CAmount TEST_BILL_ESCROW = 75 * COIN / 10;   // 7.5

// Build a fully valid ISSUE transaction with fresh keys
static CMutableTransaction MakeIssueTx(BillIssue& issueOut, CKey& keyDrawer, CKey& keyAcceptor, CKey& keyHolder)
{
    keyDrawer.MakeNewKey(true);
    keyAcceptor.MakeNewKey(true);
    keyHolder.MakeNewKey(true);

    BillIssue issue;
    issue.vchEncryptedBody = TestBody();
    issue.amount = 10 * COIN;
    issue.nMaturityHeight = 500;
    issue.nGraceBlocks = DEFAULT_BILL_GRACE_BLOCKS;
    CPubKey pubDrawer = keyDrawer.GetPubKey();
    CPubKey pubAcceptor = keyAcceptor.GetPubKey();
    CPubKey pubHolder = keyHolder.GetPubKey();
    issue.vchDrawerPubKey = std::vector<unsigned char>(pubDrawer.begin(), pubDrawer.end());
    issue.vchAcceptorPubKey = std::vector<unsigned char>(pubAcceptor.begin(), pubAcceptor.end());
    issue.vchHolderPubKey = std::vector<unsigned char>(pubHolder.begin(), pubHolder.end());

    const uint256 billID = BillIDFromBody(issue.vchEncryptedBody);
    const uint256 sighash = BillIssueSigHash(billID, issue.amount, TEST_BILL_ESCROW,
            issue.nMaturityHeight, issue.nGraceBlocks, issue.vchDrawerPubKey,
            issue.vchAcceptorPubKey, issue.vchHolderPubKey);
    BOOST_REQUIRE(keyDrawer.Sign(sighash, issue.vchDrawerSig));
    BOOST_REQUIRE(keyAcceptor.Sign(sighash, issue.vchAcceptorSig));

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_ISSUE;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << issue;
    mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());

    // funding input placeholder (prevout must be non-null for CheckTransaction)
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));

    mtx.vout.push_back(CTxOut(BILL_TITLE_VALUE, GetScriptForDestination(pubHolder.GetID())));
    mtx.vout.push_back(CTxOut(TEST_BILL_ESCROW, BillEscrowScript(billID)));

    issueOut = issue;
    return mtx;
}

BOOST_AUTO_TEST_CASE(bill_id_derivation)
{
    // Single SHA256 of the body (NOT double-SHA)
    std::vector<unsigned char> vchBody = TestBody();
    uint256 id = BillIDFromBody(vchBody);
    BOOST_CHECK(!id.IsNull());

    // Deterministic + sensitive to body changes
    BOOST_CHECK(id == BillIDFromBody(TestBody()));
    vchBody[0] ^= 1;
    BOOST_CHECK(id != BillIDFromBody(vchBody));
}

BOOST_AUTO_TEST_CASE(bill_sighash_domain_separation)
{
    const uint256 billID = BillIDFromBody(TestBody());
    const uint256 hashOutputs = uint256S("02");

    // Retire and claim messages over identical inputs must differ
    BOOST_CHECK(BillRetireSigHash(billID, hashOutputs) != BillClaimSigHash(billID, hashOutputs));

    // hashOutputs must matter (anti-replay: the signature pins the outputs)
    BOOST_CHECK(BillClaimSigHash(billID, hashOutputs) != BillClaimSigHash(billID, uint256S("03")));
}

BOOST_AUTO_TEST_CASE(bill_escrow_script)
{
    const uint256 billID = BillIDFromBody(TestBody());
    CScript script = BillEscrowScript(billID);
    BOOST_CHECK(IsBillEscrowScript(script));
    BOOST_CHECK(!IsBillEscrowScript(CScript() << OP_TRUE));
    BOOST_CHECK(!IsBillEscrowScript(GetScriptForDestination(CKeyID())));
}

BOOST_AUTO_TEST_CASE(bill_endorse_fee_floor)
{
    BOOST_CHECK_EQUAL(BillEndorseFeeFloor(1), 0);
    BOOST_CHECK_EQUAL(BillEndorseFeeFloor(BILL_ENDORSE_SOFT_CAP), 0);
    BOOST_CHECK_EQUAL(BillEndorseFeeFloor(BILL_ENDORSE_SOFT_CAP + 1), BILL_ENDORSE_BASE_FEE * 2);
    BOOST_CHECK_EQUAL(BillEndorseFeeFloor(BILL_ENDORSE_SOFT_CAP + 4), BILL_ENDORSE_BASE_FEE * 16);
}

BOOST_AUTO_TEST_CASE(bill_payload_roundtrip)
{
    BillIssue issue;
    CKey k1, k2, k3;
    CMutableTransaction mtx = MakeIssueTx(issue, k1, k2, k3);

    BillIssue decoded;
    BOOST_REQUIRE(DecodeBillPayload(mtx.vchBillPayload, decoded));
    BOOST_CHECK(decoded.vchEncryptedBody == issue.vchEncryptedBody);
    BOOST_CHECK_EQUAL(decoded.amount, issue.amount);
    BOOST_CHECK_EQUAL(decoded.nMaturityHeight, issue.nMaturityHeight);
    BOOST_CHECK(decoded.vchDrawerSig == issue.vchDrawerSig);

    // Trailing bytes are rejected
    std::vector<unsigned char> vchPadded = mtx.vchBillPayload;
    vchPadded.push_back(0x00);
    BOOST_CHECK(!DecodeBillPayload(vchPadded, decoded));
}

BOOST_AUTO_TEST_CASE(bill_tx_serialization_roundtrip)
{
    BillIssue issue;
    CKey k1, k2, k3;
    CMutableTransaction mtx = MakeIssueTx(issue, k1, k2, k3);

    // v11 trailer fields must survive tx serialization
    CTransaction tx(mtx);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx;
    CTransaction tx2(deserialize, ss);

    BOOST_CHECK_EQUAL(tx2.nVersion, TRANSACTION_BILL_VERSION);
    BOOST_CHECK_EQUAL(tx2.nBillOp, BILL_OP_ISSUE);
    BOOST_CHECK(tx2.vchBillPayload == tx.vchBillPayload);
    BOOST_CHECK(tx2.GetHash() == tx.GetHash());
}

BOOST_AUTO_TEST_CASE(bill_issue_shape_valid)
{
    BillIssue issue;
    CKey k1, k2, k3;
    CMutableTransaction mtx = MakeIssueTx(issue, k1, k2, k3);

    CValidationState state;
    BOOST_CHECK(CheckBillTransactionShape(CTransaction(mtx), state));
}

// The drawer/acceptor signatures are verified contextually (CheckBillOperation),
// not in the context-free shape check, so exercise the binding directly: any
// change to a signed field — including the posted escrow bond — must break the
// signature. This is the anti-front-run guarantee (bond bound into the sighash).
BOOST_AUTO_TEST_CASE(bill_issue_sig_binding)
{
    CKey keyDrawer;
    keyDrawer.MakeNewKey(true);
    CPubKey pub = keyDrawer.GetPubKey();
    std::vector<unsigned char> vchPub(pub.begin(), pub.end());

    const uint256 billID = BillIDFromBody(TestBody());
    const CAmount amount = 10 * COIN;
    const CAmount escrow = 75 * COIN / 10;

    const uint256 sighash = BillIssueSigHash(billID, amount, escrow, 500,
            DEFAULT_BILL_GRACE_BLOCKS, vchPub, vchPub, vchPub);
    std::vector<unsigned char> vchSig;
    BOOST_REQUIRE(keyDrawer.Sign(sighash, vchSig));
    BOOST_CHECK(pub.Verify(sighash, vchSig));

    // Front-run with a token escrow bond -> different sighash -> sig invalid
    const uint256 sighashCheapBond = BillIssueSigHash(billID, amount, 1, 500,
            DEFAULT_BILL_GRACE_BLOCKS, vchPub, vchPub, vchPub);
    BOOST_CHECK(sighash != sighashCheapBond);
    BOOST_CHECK(!pub.Verify(sighashCheapBond, vchSig));

    // Tampered face amount -> sig invalid
    BOOST_CHECK(!pub.Verify(BillIssueSigHash(billID, amount + 1, escrow, 500,
            DEFAULT_BILL_GRACE_BLOCKS, vchPub, vchPub, vchPub), vchSig));
}

BOOST_AUTO_TEST_CASE(bill_issue_shape_rejections)
{
    BillIssue issue;
    CKey k1, k2, k3;

    // Escrow output must commit to the body's bill_id
    {
        CMutableTransaction mtx = MakeIssueTx(issue, k1, k2, k3);
        mtx.vout[1].scriptPubKey = BillEscrowScript(uint256S("04"));

        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(mtx), state));
    }

    // Title output must pay the holder exactly BILL_TITLE_VALUE
    {
        CMutableTransaction mtx = MakeIssueTx(issue, k1, k2, k3);
        mtx.vout[0].nValue = BILL_TITLE_VALUE + 1;

        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(mtx), state));
    }

    // Unknown op
    {
        CMutableTransaction mtx = MakeIssueTx(issue, k1, k2, k3);
        mtx.nBillOp = 99;

        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(mtx), state));
    }

    // Oversize body
    {
        CMutableTransaction mtx = MakeIssueTx(issue, k1, k2, k3);
        BillIssue big = issue;
        big.vchEncryptedBody.assign(MAX_BILL_BODY_BYTES + 1, 0x42);
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << big;
        mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());

        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(mtx), state));
    }
}

BOOST_AUTO_TEST_CASE(bill_endorsement_sig)
{
    CKey keyFrom;
    keyFrom.MakeNewKey(true);
    CKey keyTo;
    keyTo.MakeNewKey(true);
    CPubKey pubFrom = keyFrom.GetPubKey();
    CPubKey pubTo = keyTo.GetPubKey();

    const uint256 billID = BillIDFromBody(TestBody());
    std::vector<unsigned char> vchTo(pubTo.begin(), pubTo.end());

    const uint256 sighash = BillEndorseSigHash(billID, vchTo, 100);
    std::vector<unsigned char> vchSig;
    BOOST_REQUIRE(keyFrom.Sign(sighash, vchSig));

    BOOST_CHECK(pubFrom.Verify(sighash, vchSig));
    // Signature does not verify for a different height or endorsee
    BOOST_CHECK(!pubFrom.Verify(BillEndorseSigHash(billID, vchTo, 101), vchSig));
    std::vector<unsigned char> vchFrom(pubFrom.begin(), pubFrom.end());
    BOOST_CHECK(!pubFrom.Verify(BillEndorseSigHash(billID, vchFrom, 100), vchSig));
}

BOOST_AUTO_TEST_CASE(bill_record_serialization)
{
    CBill bill;
    bill.nBillID = 7;
    bill.billID = BillIDFromBody(TestBody());
    bill.vchEncryptedBody = TestBody();
    bill.amount = 10 * COIN;
    bill.amountEscrow = 75 * COIN / 10;
    bill.nIssuedHeight = 10;
    bill.nMaturityHeight = 500;
    bill.nGraceBlocks = DEFAULT_BILL_GRACE_BLOCKS;
    bill.status = BILL_STATUS_ACTIVE;
    bill.outEscrow = COutPoint(uint256S("05"), 1);
    bill.outTitle = COutPoint(uint256S("05"), 0);

    BillEndorsement e;
    e.nAtHeight = 42;
    bill.vEndorsement.push_back(e);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << bill;
    CBill bill2;
    ss >> bill2;

    BOOST_CHECK_EQUAL(bill2.nBillID, bill.nBillID);
    BOOST_CHECK(bill2.billID == bill.billID);
    BOOST_CHECK_EQUAL(bill2.amount, bill.amount);
    BOOST_CHECK_EQUAL(bill2.status, bill.status);
    BOOST_CHECK_EQUAL(bill2.vEndorsement.size(), 1);
    BOOST_CHECK_EQUAL(bill2.vEndorsement[0].nAtHeight, 42);
    BOOST_CHECK(bill2.outTitle == bill.outTitle);
}

BOOST_AUTO_TEST_SUITE_END()
