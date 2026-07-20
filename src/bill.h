// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BILL_H
#define BITCOIN_BILL_H

#include <amount.h>
#include <pubkey.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <string>
#include <vector>

class CValidationState;

//
// Bills of exchange (Phase 3.3).
//
// A bill is a unique, stateful credit instrument: identity is
// bill_id = sha256(encrypted_body) (consensus never decrypts the body), the
// drawee/acceptor posts a sidechain-native escrow bond at issue, ownership is
// a title UTXO advanced by endorsement, and the bill terminates Retired
// (drawee pays face to the current holder) or Defaulted (maturity + grace
// elapsed; the escrow pays out to the current holder).
//
// All constants are PROVISIONAL (B-1) - revisit at M1-package time.
//

// Bill operations carried by TRANSACTION_BILL_VERSION transactions
static const uint8_t BILL_OP_ISSUE   = 1;
static const uint8_t BILL_OP_ENDORSE = 2;
static const uint8_t BILL_OP_RETIRE  = 3;
static const uint8_t BILL_OP_CLAIM   = 4;

// On-chain bill status (Issued / Endorsed collapse to active)
static const char BILL_STATUS_ACTIVE    = 'a';
static const char BILL_STATUS_RETIRED   = 'r';
static const char BILL_STATUS_DEFAULTED = 'd';
// Reserved for the dispute module - not reachable in v1. PROVISIONAL (B-1 / D3)
static const char BILL_STATUS_DISPUTED  = 'x';

// Encrypted body size cap. PROVISIONAL (B-1)
static const size_t MAX_BILL_BODY_BYTES = 4096;

// Grace period: default and cap. PROVISIONAL (B-1, Tx-5)
static const uint32_t DEFAULT_BILL_GRACE_BLOCKS = 1008;
static const uint32_t MAX_BILL_GRACE_BLOCKS = 52560;

// Maturity may be at most this many blocks ahead of issuance (~10 years at
// 10-min blocks). Bounds the tenor to a sane range and — with the grace cap —
// keeps maturity_height + grace_blocks far below uint32 overflow. Consensus
// only enforces this outer bound; the ≤12-month real-bills discipline is
// app-layer. PROVISIONAL (B-1)
static const uint32_t MAX_BILL_TENOR_BLOCKS = 525600;

// Endorsement-chain DoS rule: fee doubles per endorsement past the soft cap,
// no hard cap. PROVISIONAL (B-1, Tx-4)
static const size_t BILL_ENDORSE_SOFT_CAP = 16;
static const CAmount BILL_ENDORSE_BASE_FEE = 10000;

// Value carried by the title (ownership) output - above dust. PROVISIONAL (B-1)
static const CAmount BILL_TITLE_VALUE = 10000;

// Endorsement record atHeight must be within this many blocks below the
// height it connects at (records stay accurate, txs survive small reorgs
// and mempool delay). PROVISIONAL (B-1)
static const uint32_t BILL_ENDORSE_HEIGHT_SLACK = 64;

/** One link of the endorsement chain (ARCH §4): signed over
 * (bill_id, to_pk, at_height) with a domain tag. */
struct BillEndorsement {
    std::vector<unsigned char> vchFrom;   // 33-byte compressed pubkey
    std::vector<unsigned char> vchTo;
    uint32_t nAtHeight;
    std::vector<unsigned char> vchSig;

    BillEndorsement() : nAtHeight(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vchFrom);
        READWRITE(vchTo);
        READWRITE(nAtHeight);
        READWRITE(vchSig);
    }
};

/** The consensus bill record persisted in BillDB. */
struct CBill {
    uint32_t nBillID;                             // dense id (BitAsset nID pattern); coin tags carry this
    uint256 billID;                               // sha256(encrypted_body) - canonical identity
    std::vector<unsigned char> vchEncryptedBody;  // opaque to consensus
    CAmount amount;                               // face, base-coin sats (D2)
    CAmount amountEscrow;                         // bond actually posted (issue vout[1] value)
    uint32_t nIssuedHeight;
    uint32_t nMaturityHeight;
    uint32_t nGraceBlocks;
    std::vector<unsigned char> vchDrawerPubKey;
    std::vector<unsigned char> vchAcceptorPubKey; // drawee; added to the Tx-9 set per D1
    std::vector<unsigned char> vchHolderPubKey;   // current holder
    std::vector<BillEndorsement> vEndorsement;
    char status;
    uint256 txidIssue;
    COutPoint outEscrow;                          // escrow_lock_ref, sidechain-native (D1)
    COutPoint outTitle;                           // current title (ownership) UTXO

    CBill() : nBillID(0), amount(0), amountEscrow(0), nIssuedHeight(0),
              nMaturityHeight(0), nGraceBlocks(0), status(BILL_STATUS_ACTIVE) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBillID);
        READWRITE(billID);
        READWRITE(vchEncryptedBody);
        READWRITE(amount);
        READWRITE(amountEscrow);
        READWRITE(nIssuedHeight);
        READWRITE(nMaturityHeight);
        READWRITE(nGraceBlocks);
        READWRITE(vchDrawerPubKey);
        READWRITE(vchAcceptorPubKey);
        READWRITE(vchHolderPubKey);
        READWRITE(vEndorsement);
        READWRITE(status);
        READWRITE(txidIssue);
        READWRITE(outEscrow);
        READWRITE(outTitle);
    }
};

//
// v11 trailer payloads, one per BILL_OP_*
//

struct BillIssue {
    std::vector<unsigned char> vchEncryptedBody;
    CAmount amount;                               // face
    uint32_t nMaturityHeight;
    uint32_t nGraceBlocks;
    std::vector<unsigned char> vchDrawerPubKey;
    std::vector<unsigned char> vchAcceptorPubKey;
    std::vector<unsigned char> vchHolderPubKey;
    std::vector<unsigned char> vchDrawerSig;      // over BillIssueSigHash
    std::vector<unsigned char> vchAcceptorSig;    // over BillIssueSigHash - this IS acceptance

    BillIssue() : amount(0), nMaturityHeight(0), nGraceBlocks(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vchEncryptedBody);
        READWRITE(amount);
        READWRITE(nMaturityHeight);
        READWRITE(nGraceBlocks);
        READWRITE(vchDrawerPubKey);
        READWRITE(vchAcceptorPubKey);
        READWRITE(vchHolderPubKey);
        READWRITE(vchDrawerSig);
        READWRITE(vchAcceptorSig);
    }
};

struct BillEndorse {
    uint32_t nBillID;
    BillEndorsement endorsement;

    BillEndorse() : nBillID(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBillID);
        READWRITE(endorsement);
    }
};

struct BillRetire {
    uint32_t nBillID;
    std::vector<unsigned char> vchAcceptorSig;    // over BillRetireSigHash

    BillRetire() : nBillID(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBillID);
        READWRITE(vchAcceptorSig);
    }
};

struct BillClaim {
    uint32_t nBillID;
    std::vector<unsigned char> vchHolderSig;      // over BillClaimSigHash

    BillClaim() : nBillID(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBillID);
        READWRITE(vchHolderSig);
    }
};

/** bill_id = single sha256 of the encrypted body (ARCH §4). */
uint256 BillIDFromBody(const std::vector<unsigned char>& vchBody);

//
// Domain-separated signature messages. The legacy input sighash does not
// cover v11 trailer fields, so every payload field a party relies on MUST be
// bound by one of these payload-level signatures.
//
uint256 BillIssueSigHash(const uint256& billID, const CAmount& amount, const CAmount& amountEscrow, uint32_t nMaturityHeight, uint32_t nGraceBlocks, const std::vector<unsigned char>& vchDrawerPubKey, const std::vector<unsigned char>& vchAcceptorPubKey, const std::vector<unsigned char>& vchHolderPubKey);
uint256 BillEndorseSigHash(const uint256& billID, const std::vector<unsigned char>& vchTo, uint32_t nAtHeight);

// Retire / claim spend the escrow coin with an EMPTY scriptSig, so nothing
// else pins the transaction's outputs - these signatures bind hashOutputs
// (BIP143-style) or a miner could replay them into a transaction paying
// itself.
uint256 BillHashOutputs(const CTransaction& tx);
uint256 BillRetireSigHash(const uint256& billID, const uint256& hashOutputs);
uint256 BillClaimSigHash(const uint256& billID, const uint256& hashOutputs);

/** The escrow output script: <bill_id> OP_DROP OP_TRUE - open at script
 * layer, locked by the consensus spend rules on fBillEscrow coins. */
CScript BillEscrowScript(const uint256& billID);
bool IsBillEscrowScript(const CScript& script);

/** P2PKH script for a compressed pubkey (payments to holder / title outputs). */
CScript BillScriptForPubKey(const std::vector<unsigned char>& vchPubKey);

/** Deserialize a v11 trailer payload; false on failure or trailing bytes. */
template <typename T>
bool DecodeBillPayload(const std::vector<unsigned char>& vch, T& payload);

/** Context-free checks for a v11 transaction (shape, sizes, payload
 * signatures). Called from CheckTransaction. */
bool CheckBillTransactionShape(const CTransaction& tx, CValidationState& state);

/** Sum of tx outputs paying P2PKH(vchPubKey). */
CAmount BillValuePaidTo(const CTransaction& tx, const std::vector<unsigned char>& vchPubKey);

/** The consensus fee floor for an endorsement making the chain nLen long.
 * PROVISIONAL (B-1, Tx-4): base fee doubles per endorsement past the soft cap. */
CAmount BillEndorseFeeFloor(size_t nLen);

#endif // BITCOIN_BILL_H
