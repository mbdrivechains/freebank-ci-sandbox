// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <l1client.h>

#include <chainparams.h>
#include <chainparamsbase.h>
#include <core_io.h>
#include <sidechain.h>
#include <uint256.h>
#include <univalue.h>
#include <utilmoneystr.h>
#include <utilstrencodings.h>
#include <streams.h>
#include <txdb.h>
#include <util.h>
#include <validation.h>

#include <algorithm>
#include <cstdio>
#include <mutex>
#include <set>
#include <sstream>
#include <string>

#include <sys/wait.h>

#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/foreach.hpp>
#include <boost/property_tree/json_parser.hpp>

using boost::asio::ip::tcp;

//
// JsonRpcL1Client - the legacy drivechain JSON-RPC transport. Method bodies
// moved verbatim from SidechainClient (which is now a facade over L1Client).
//

class JsonRpcL1Client final : public L1Client
{
public:
    bool BroadcastWithdrawalBundle(const std::string& hex) override;
    std::vector<SidechainDeposit> UpdateDeposits(const uint256& hashLastDeposit, const uint32_t nLastBurnIndex) override;
    bool VerifyDeposit(const uint256& hashMainBlock, const uint256& txid, const int nTx) override;
    bool VerifyBMM(const uint256& hashMainBlock, const uint256& hashBMM, uint256& txid, uint32_t& nTime) override;
    uint256 SendBMMRequest(const uint256& hashBMM, const uint256& hashBlockMain, int nHeight, CAmount amount) override;
    bool GetCTIP(std::pair<uint256, uint32_t>& ctip) override;
    bool GetAverageFees(int nBlocks, int nStartHeight, CAmount& nAverageFees) override;
    bool GetBlockCount(int& nBlocks) override;
    bool GetWorkScore(const uint256& hash, int& nWorkScore) override;
    bool ListWithdrawalBundleStatus(std::vector<uint256>& vHashWithdrawalBundle) override;
    bool GetBlockHash(int nHeight, uint256& hashBlock) override;
    bool GetAncestorHashes(const uint256& hashBlock, int nHeight, uint32_t nMax, std::vector<uint256>& vHash) override;
    bool HaveSpentWithdrawalBundle(const uint256& hash) override;
    bool HaveFailedWithdrawalBundle(const uint256& hash) override;

private:
    /*
     * Send json request to local node
     */
    bool SendRequestToMainchain(const std::string& json, boost::property_tree::ptree& ptree);
};

//
// EnforcerL1Client - reads mainchain state from the CUSF bip300301_enforcer
// ValidatorService (gRPC) by shelling out to grpcurl. Read-path only: the
// write-path (SendBMMRequest, BroadcastWithdrawalBundle) and the deposit /
// withdrawal-status queries need the enforcer wallet service and land in
// Phase 2b - until then those methods log once and report failure.
//

class EnforcerL1Client final : public L1Client
{
public:
    bool BroadcastWithdrawalBundle(const std::string& hex) override;
    std::vector<SidechainDeposit> UpdateDeposits(const uint256& hashLastDeposit, const uint32_t nLastBurnIndex) override;
    bool VerifyDeposit(const uint256& hashMainBlock, const uint256& txid, const int nTx) override;
    bool VerifyBMM(const uint256& hashMainBlock, const uint256& hashBMM, uint256& txid, uint32_t& nTime) override;
    uint256 SendBMMRequest(const uint256& hashBMM, const uint256& hashBlockMain, int nHeight, CAmount amount) override;
    bool GetCTIP(std::pair<uint256, uint32_t>& ctip) override;
    bool GetAverageFees(int nBlocks, int nStartHeight, CAmount& nAverageFees) override;
    bool GetBlockCount(int& nBlocks) override;
    bool GetWorkScore(const uint256& hash, int& nWorkScore) override;
    bool ListWithdrawalBundleStatus(std::vector<uint256>& vHashWithdrawalBundle) override;
    bool GetBlockHash(int nHeight, uint256& hashBlock) override;
    bool GetAncestorHashes(const uint256& hashBlock, int nHeight, uint32_t nMax, std::vector<uint256>& vHash) override;
    bool HaveSpentWithdrawalBundle(const uint256& hash) override;
    bool HaveFailedWithdrawalBundle(const uint256& hash) override;

    /* The init-time REST reachability probe borrows the private RestGet. */
    friend bool ::ProbeMainchainRest(std::string& strError);

private:
    /*
     * Invoke a ValidatorService method through grpcurl and parse the JSON
     * reply. The enforcer is only ever invoked at runtime by service name -
     * nothing of it is vendored or linked.
     */
    bool CallValidator(const std::string& strMethod, const std::string& strRequest, UniValue& result);

    /* Invoke a WalletService method (write-path). Same grpcurl shell-out. */
    bool CallWallet(const std::string& strMethod, const std::string& strRequest, UniValue& result);

    /* Shared grpcurl shell-out for any enforcer service. */
    bool CallEnforcer(const std::string& strService, const std::string& strMethod, const std::string& strRequest, UniValue& result);

    /* GetChainTip convenience wrapper */
    bool GetChainTip(L1BlockHeader& header);

    /* GetBlockHeaderInfo for hashBlock plus up to nMaxAncestors ancestors */
    bool GetHeaderInfos(const uint256& hashBlock, uint32_t nMaxAncestors, std::vector<L1BlockHeader>& vHeader);

    /* Mainchain REST helpers (-mainchainrest=<host:port>) for the deposit path:
     * the enforcer's Deposit event lacks the raw tx (needed for CTIP-chain
     * ordering + cumulative CTIP amount) and the tx-index-in-block (nTx), so we
     * fetch them from the mainchain node's REST interface. */
    bool RestGet(const std::string& strPath, std::string& strBody);
    bool RestGetRawTx(const uint256& txid, CMutableTransaction& tx);
    bool RestGetBlockTxids(const uint256& hashBlock, std::vector<uint256>& vTxid);

    /* Fetch all withdrawal-bundle events for THIS_SIDECHAIN via GetTwoWayPegData. */
    bool FetchWithdrawalEvents(std::vector<L1WithdrawalEvent>& vEvents);

    /* Log a message once per key */
    void LogOnce(const std::string& strKey, const std::string& strMessage);

    /* Log an unimplemented-method warning once per method */
    void LogUnimplemented(const std::string& strMethod, const std::string& strReason);

    std::mutex mutexLogged;
    std::set<std::string> setLogged;
};

//
// Enforcer wire helpers
//

uint256 Uint256FromConsensusHex(const std::string& strHex)
{
    if (strHex.size() != 64 || !IsHex(strHex))
        return uint256();

    // ConsensusHex is internal byte order; uint256's string form is the
    // reverse (display order)
    std::vector<unsigned char> vch = ParseHex(strHex);
    uint256 ret;
    std::copy(vch.begin(), vch.end(), ret.begin());
    return ret;
}

std::string ConsensusHexFromUint256(const uint256& hash)
{
    return HexStr(hash.begin(), hash.end());
}

/** Read a {"hex": "..."} wrapper (ReverseHex / ConsensusHex / Hex). */
static bool GetHexField(const UniValue& obj, std::string& strHex)
{
    if (!obj.isObject())
        return false;

    const UniValue& hex = find_value(obj, "hex");
    if (!hex.isStr())
        return false;

    strHex = hex.get_str();
    return IsHex(strHex);
}

/** Parse one BlockHeaderInfo object. proto3 JSON omits zero-value fields. */
static bool ParseHeaderObject(const UniValue& obj, L1BlockHeader& header)
{
    if (!obj.isObject())
        return false;

    std::string strHash;
    if (!GetHexField(find_value(obj, "blockHash"), strHash))
        return false;
    header.hashBlock = uint256S(strHash);

    std::string strPrevHash;
    if (GetHexField(find_value(obj, "prevBlockHash"), strPrevHash))
        header.hashPrevBlock = uint256S(strPrevHash);
    else
        header.hashPrevBlock.SetNull();

    // Absent height / timestamp = proto3 zero default (genesis / unset)
    const UniValue& height = find_value(obj, "height");
    header.nHeight = height.isNum() ? height.get_int() : 0;

    const UniValue& timestamp = find_value(obj, "timestamp");
    if (timestamp.isNull())
        header.nTime = 0;
    else
        header.nTime = (uint32_t)atoi64(timestamp.getValStr());

    return true;
}

bool ParseEnforcerChainTip(const UniValue& response, L1BlockHeader& header)
{
    if (!response.isObject())
        return false;

    return ParseHeaderObject(find_value(response, "blockHeaderInfo"), header);
}

bool ParseEnforcerHeaderInfos(const UniValue& response, std::vector<L1BlockHeader>& vHeader)
{
    vHeader.clear();

    if (!response.isObject())
        return false;

    const UniValue& infos = find_value(response, "headerInfos");
    if (!infos.isArray())
        return false;

    for (size_t i = 0; i < infos.size(); i++) {
        L1BlockHeader header;
        if (!ParseHeaderObject(infos[i], header))
            return false;

        vHeader.push_back(header);
    }

    return !vHeader.empty();
}

bool ParseEnforcerBmmCommitment(const UniValue& response, bool& fBlockFound, bool& fHaveCommitment, uint256& hashCommitment)
{
    fBlockFound = false;
    fHaveCommitment = false;
    hashCommitment.SetNull();

    if (!response.isObject())
        return false;

    if (find_value(response, "blockNotFound").isObject())
        return true;

    const UniValue& commitment = find_value(response, "commitment");
    if (!commitment.isObject())
        return false;

    fBlockFound = true;

    // Block known, but no h* committed for this sidechain
    std::string strHex;
    if (!GetHexField(find_value(commitment, "commitment"), strHex))
        return true;

    // BlockInfo.bmm_commitment is ConsensusHex (internal byte order)
    hashCommitment = Uint256FromConsensusHex(strHex);
    fHaveCommitment = !hashCommitment.IsNull();

    return true;
}

bool ParseEnforcerBlockDepositTxids(const UniValue& response, std::vector<uint256>& vTxid)
{
    vTxid.clear();

    if (!response.isObject())
        return false;

    const UniValue& infos = find_value(response, "infos");
    if (!infos.isArray() || infos.empty())
        return false;

    // Ancestors are newest-first; [0] is the requested block
    const UniValue& blockInfo = find_value(infos[0], "blockInfo");
    if (!blockInfo.isObject())
        return true;

    const UniValue& events = find_value(blockInfo, "events");
    if (!events.isArray())
        return true;

    for (size_t i = 0; i < events.size(); i++) {
        const UniValue& deposit = find_value(events[i], "deposit");
        if (!deposit.isObject())
            continue;

        std::string strTxid;
        if (!GetHexField(find_value(find_value(deposit, "outpoint"), "txid"), strTxid))
            continue;

        vTxid.push_back(uint256S(strTxid));
    }

    return true;
}

bool ParseEnforcerCtip(const UniValue& response, uint256& txid, uint32_t& n)
{
    if (!response.isObject())
        return false;

    const UniValue& ctip = find_value(response, "ctip");
    if (!ctip.isObject())
        return false;

    std::string strTxid;
    if (!GetHexField(find_value(ctip, "txid"), strTxid))
        return false;

    txid = uint256S(strTxid);

    // Absent vout = proto3 zero default
    const UniValue& vout = find_value(ctip, "vout");
    n = vout.isNum() ? (uint32_t)vout.get_int() : 0;

    return true;
}

bool ParseEnforcerWithdrawalEvents(const UniValue& response, std::vector<L1WithdrawalEvent>& vEvents)
{
    vEvents.clear();

    if (!response.isObject())
        return false;

    const UniValue& blocks = find_value(response, "blocks");
    if (!blocks.isArray())
        return true; // no peg data is a valid empty result

    for (size_t b = 0; b < blocks.size(); b++) {
        // Block hash (ReverseHex == display order) - null if absent
        uint256 hashBlock;
        std::string strBlockHash;
        if (GetHexField(find_value(find_value(blocks[b], "blockHeaderInfo"), "blockHash"), strBlockHash))
            hashBlock = uint256S(strBlockHash);

        const UniValue& events = find_value(find_value(blocks[b], "blockInfo"), "events");
        if (!events.isArray())
            continue;

        for (size_t e = 0; e < events.size(); e++) {
            const UniValue& wb = find_value(events[e], "withdrawalBundle");
            if (!wb.isObject())
                continue;

            L1WithdrawalEvent ev;
            ev.hashMainBlock = hashBlock;
            std::string strM6;
            // m6id is ConsensusHex (internal byte order), like bmm_commitment
            if (!GetHexField(find_value(wb, "m6id"), strM6))
                continue;
            ev.m6id = Uint256FromConsensusHex(strM6);
            if (ev.m6id.IsNull())
                continue;

            const UniValue& event = find_value(wb, "event");
            if (find_value(event, "succeeded").isObject())
                ev.status = 'S';
            else if (find_value(event, "failed").isObject())
                ev.status = 'F';
            else if (find_value(event, "submitted").isObject())
                ev.status = 'U';
            else
                continue;

            vEvents.push_back(ev);
        }
    }
    return true;
}

//
// EnforcerL1Client
//

bool EnforcerL1Client::CallEnforcer(const std::string& strService, const std::string& strMethod, const std::string& strRequest, UniValue& result)
{
    // Requests are built internally from hex strings and integers only; the
    // binary and address come from the node operator's own configuration.
    // (base64 in the withdrawal-bundle payload has no single quote, so the
    // single-quoted -d '...' stays safe.)
    if (strRequest.find('\'') != std::string::npos)
        return false;

    std::string strBin = gArgs.GetArg("-grpcurlbin", "grpcurl");
    std::string strAddr = gArgs.GetArg("-enforceraddr", "127.0.0.1:50051");

    std::string strCommand = strBin + " -plaintext -max-time 15 -d '" + strRequest + "' " +
        strAddr + " " + strService + "/" + strMethod + " 2>/dev/null";

    FILE* pipe = popen(strCommand.c_str(), "r");
    if (!pipe) {
        LogPrintf("ERROR Enforcer client failed to run grpcurl (%s)\n", strMethod);
        return false;
    }

    std::string strOutput;
    char buffer[4096];
    size_t nRead;
    while ((nRead = fread(buffer, 1, sizeof(buffer), pipe)) > 0)
        strOutput.append(buffer, nRead);

    int status = pclose(pipe);
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        // 127 = the shell couldn't find the grpcurl binary at all - that is
        // misconfiguration, not a routine failure, so say so once
        if (status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 127)
            LogOnce("grpcurl-missing", "ERROR Enforcer client: grpcurl binary '" + strBin +
                "' not found - the enforcer transport cannot work; set -grpcurlbin\n");
        // Otherwise can be enabled for debug -- too noisy (includes routine
        // "block not found" gRPC errors)
        // LogPrintf("ERROR Enforcer client %s failed\n", strMethod);
        return false;
    }

    if (!result.read(strOutput)) {
        LogPrintf("ERROR Enforcer client %s returned unparseable JSON\n", strMethod);
        return false;
    }

    return true;
}

bool EnforcerL1Client::CallValidator(const std::string& strMethod, const std::string& strRequest, UniValue& result)
{
    return CallEnforcer("cusf.mainchain.v1.ValidatorService", strMethod, strRequest, result);
}

bool EnforcerL1Client::CallWallet(const std::string& strMethod, const std::string& strRequest, UniValue& result)
{
    return CallEnforcer("cusf.mainchain.v1.WalletService", strMethod, strRequest, result);
}

bool EnforcerL1Client::GetChainTip(L1BlockHeader& header)
{
    UniValue result(UniValue::VOBJ);
    if (!CallValidator("GetChainTip", "{}", result))
        return false;

    return ParseEnforcerChainTip(result, header);
}

bool EnforcerL1Client::GetHeaderInfos(const uint256& hashBlock, uint32_t nMaxAncestors, std::vector<L1BlockHeader>& vHeader)
{
    std::string strRequest = "{\"block_hash\": {\"hex\": \"" + hashBlock.ToString() + "\"}";
    if (nMaxAncestors > 0)
        strRequest += ", \"max_ancestors\": " + std::to_string(nMaxAncestors);
    strRequest += "}";

    UniValue result(UniValue::VOBJ);
    if (!CallValidator("GetBlockHeaderInfo", strRequest, result))
        return false;

    return ParseEnforcerHeaderInfos(result, vHeader);
}

void EnforcerL1Client::LogOnce(const std::string& strKey, const std::string& strMessage)
{
    std::lock_guard<std::mutex> lock(mutexLogged);
    if (setLogged.count(strKey))
        return;

    setLogged.insert(strKey);
    LogPrintf("%s", strMessage);
}

void EnforcerL1Client::LogUnimplemented(const std::string& strMethod, const std::string& strReason)
{
    LogOnce(strMethod, "Enforcer client: " + strMethod +
        " is not available on the enforcer transport yet (" + strReason + ")\n");
}

bool EnforcerL1Client::BroadcastWithdrawalBundle(const std::string& hex)
{
    // The enforcer expects a BLINDED M6: a ZERO-input tx (the input spending the
    // sidechain CTIP is implied), serialized in LEGACY (non-witness) form. Our
    // chassis bundle carries a null-prevout placeholder input and would be
    // rejected ("Blinded M6 error: Inputs must be empty"), so we strip the inputs
    // and re-serialize without the witness marker (a 0-input tx in the segwit
    // encoding would be misread as a witness marker).
    if (!IsHex(hex))
        return false;

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, hex))
        return false;

    mtx.vin.clear();

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    ss << CTransaction(mtx);
    std::vector<unsigned char> vch(ss.begin(), ss.end());
    std::string strB64 = EncodeBase64(vch.data(), vch.size());

    std::string strRequest = "{\"sidechain_id\": " + std::to_string(THIS_SIDECHAIN) +
        ", \"transaction\": \"" + strB64 + "\"}";

    UniValue result(UniValue::VOBJ);
    if (!CallWallet("BroadcastWithdrawalBundle", strRequest, result))
        return false;

    // A successful call registers the (blinded) bundle with the enforcer; its
    // block producer then proposes it (M3) and acks it (M4) via generate_blocks
    // / getblocktemplate, driving it to the M6 payout once workscore is reached.
    return true;
}

//
// Mainchain REST client + deposit parsing (enforcer transport deposit path)
//

bool EnforcerL1Client::RestGet(const std::string& strPath, std::string& strBody)
{
    std::string strHostPort = gArgs.GetArg("-mainchainrest", DEFAULT_MAINCHAIN_REST);
    if (strHostPort.empty())
        return false;

    std::string strHost = strHostPort;
    std::string strPort = "8332";
    size_t colon = strHostPort.rfind(':');
    if (colon != std::string::npos) {
        strHost = strHostPort.substr(0, colon);
        strPort = strHostPort.substr(colon + 1);
    }

    try {
        boost::asio::io_service io_service;
        tcp::resolver resolver(io_service);
        tcp::resolver::query query(strHost, strPort);
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
        tcp::resolver::iterator end;

        tcp::socket socket(io_service);
        boost::system::error_code error = boost::asio::error::host_not_found;
        while (error && endpoint_iterator != end) {
            socket.close();
            socket.connect(*endpoint_iterator++, error);
        }
        if (error) throw boost::system::system_error(error);

        // HTTP/1.0 + Connection: close -> a simple close-delimited body (no
        // chunked-encoding parsing needed)
        boost::asio::streambuf output;
        std::ostream os(&output);
        os << "GET " << strPath << " HTTP/1.0\r\n";
        os << "Host: " << strHost << "\r\n";
        os << "Connection: close\r\n\r\n";
        boost::asio::write(socket, output);

        std::string data;
        for (;;) {
            boost::array<char, 8192> buf;
            boost::system::error_code e;
            size_t sz = socket.read_some(boost::asio::buffer(buf), e);
            data.insert(data.size(), buf.data(), sz);
            if (e == boost::asio::error::eof)
                break;
            else if (e)
                throw boost::system::system_error(e);
        }

        size_t sp = data.find(' ');
        if (sp == std::string::npos)
            return false;
        int code = atoi(data.substr(sp + 1, 4).c_str());
        if (code != 200)
            return false;

        size_t bodyStart = data.find("\r\n\r\n");
        if (bodyStart == std::string::npos)
            return false;
        strBody = data.substr(bodyStart + 4);
        return true;
    } catch (std::exception& e) {
        LogPrintf("ERROR Enforcer REST GET %s: %s\n", strPath, e.what());
        return false;
    }
}

bool ProbeMainchainRest(std::string& strError)
{
    EnforcerL1Client client;
    std::string strBody;
    if (client.RestGet("/rest/chaininfo.json", strBody) && !strBody.empty())
        return true;
    strError = strprintf("mainchain REST endpoint %s did not answer /rest/chaininfo.json",
                         gArgs.GetArg("-mainchainrest", DEFAULT_MAINCHAIN_REST));
    return false;
}

bool EnforcerL1Client::RestGetRawTx(const uint256& txid, CMutableTransaction& tx)
{
    std::string body;
    if (!RestGet("/rest/tx/" + txid.ToString() + ".hex", body))
        return false;

    while (!body.empty() && (body.back() == '\n' || body.back() == '\r' || body.back() == ' '))
        body.pop_back();

    if (!IsHex(body))
        return false;

    return DecodeHexTx(tx, body);
}

bool EnforcerL1Client::RestGetBlockTxids(const uint256& hashBlock, std::vector<uint256>& vTxid)
{
    vTxid.clear();

    std::string body;
    if (!RestGet("/rest/block/notxdetails/" + hashBlock.ToString() + ".json", body))
        return false;

    UniValue obj;
    if (!obj.read(body) || !obj.isObject())
        return false;

    const UniValue& tx = find_value(obj, "tx");
    if (!tx.isArray())
        return false;

    for (size_t i = 0; i < tx.size(); i++) {
        if (!tx[i].isStr())
            return false;
        vTxid.push_back(uint256S(tx[i].get_str()));
    }
    return true;
}

// One enforcer Deposit event, flattened. output.address is a Hex of the ASCII
// bytes of the sidechain address string (== the jsonrpc strdest, verified
// live), so we decode it back to the string. value_sats is deliberately NOT
// kept: it is the deposit INCREMENT, whereas the chassis needs the cumulative
// CTIP value (read from the raw tx's burn output) and computes the delta itself.
struct EnfDep {
    uint64_t seq;
    uint256 txid;
    uint32_t vout;
    std::string strDest;
    uint256 hashBlock;
};

static bool ParseEnforcerDeposits(const UniValue& response, std::vector<EnfDep>& vDeposits)
{
    vDeposits.clear();

    if (!response.isObject())
        return false;

    const UniValue& blocks = find_value(response, "blocks");
    if (!blocks.isArray())
        return true; // no peg data is a valid empty result

    for (size_t b = 0; b < blocks.size(); b++) {
        std::string strBlockHash;
        if (!GetHexField(find_value(find_value(blocks[b], "blockHeaderInfo"), "blockHash"), strBlockHash))
            continue;
        uint256 hashBlock = uint256S(strBlockHash);

        const UniValue& events = find_value(find_value(blocks[b], "blockInfo"), "events");
        if (!events.isArray())
            continue;

        for (size_t e = 0; e < events.size(); e++) {
            const UniValue& dep = find_value(events[e], "deposit");
            if (!dep.isObject())
                continue;

            EnfDep d;
            d.hashBlock = hashBlock;

            const UniValue& seq = find_value(dep, "sequenceNumber");
            d.seq = seq.isNull() ? 0 : (uint64_t)atoi64(seq.getValStr());

            const UniValue& outpoint = find_value(dep, "outpoint");
            std::string strTxid;
            if (!GetHexField(find_value(outpoint, "txid"), strTxid))
                continue;
            d.txid = uint256S(strTxid);

            const UniValue& vout = find_value(outpoint, "vout");
            d.vout = vout.isNum() ? (uint32_t)vout.get_int() : 0;

            std::string strAddrHex;
            if (!GetHexField(find_value(find_value(dep, "output"), "address"), strAddrHex))
                continue;
            std::vector<unsigned char> vch = ParseHex(strAddrHex);
            d.strDest = std::string(vch.begin(), vch.end());

            vDeposits.push_back(d);
        }
    }
    return true;
}

std::vector<SidechainDeposit> EnforcerL1Client::UpdateDeposits(const uint256& hashLastDeposit, const uint32_t nLastBurnIndex)
{
    std::vector<SidechainDeposit> incoming;

    if (gArgs.GetArg("-mainchainrest", DEFAULT_MAINCHAIN_REST).empty()) {
        LogUnimplemented("UpdateDeposits", "set -mainchainrest=<host:port> to enable enforcer deposit crediting");
        return incoming;
    }

    // Enforcer deposit events (across the full range up to the tip). This is a
    // full rescan each call (O(all deposits)) - a cursor optimisation is a known
    // follow-up; the downstream HaveDepositNonAmount dedup is the correctness
    // backstop.
    L1BlockHeader tip;
    if (!GetChainTip(tip))
        return incoming;

    std::string strRequest = "{\"sidechain_id\": " + std::to_string(THIS_SIDECHAIN) +
        ", \"end_block_hash\": {\"hex\": \"" + tip.hashBlock.ToString() + "\"}}";

    UniValue result(UniValue::VOBJ);
    if (!CallValidator("GetTwoWayPegData", strRequest, result))
        return incoming;

    std::vector<EnfDep> vDep;
    if (!ParseEnforcerDeposits(result, vDep))
        return incoming;

    // CTIP order = sequence-number ascending (each deposit spends the prior CTIP)
    std::sort(vDep.begin(), vDep.end(), [](const EnfDep& a, const EnfDep& b) { return a.seq < b.seq; });

    // Skip everything up to and including the caller's last-processed deposit
    size_t startIdx = 0;
    if (!hashLastDeposit.IsNull()) {
        for (size_t i = 0; i < vDep.size(); i++) {
            if (vDep[i].txid == hashLastDeposit && vDep[i].vout == nLastBurnIndex) {
                startIdx = i + 1;
                break;
            }
        }
    }

    // Reconstruct each SidechainDeposit byte-identically to the jsonrpc path.
    // All-or-nothing: a single REST failure fails the whole batch closed, so
    // SortDeposits never sees a gap in the CTIP chain (which would credit 0).
    for (size_t i = startIdx; i < vDep.size(); i++) {
        const EnfDep& d = vDep[i];
        SidechainDeposit deposit;
        deposit.nSidechain = THIS_SIDECHAIN;
        deposit.strDest = d.strDest;
        deposit.nBurnIndex = d.vout;
        deposit.hashMainchainBlock = d.hashBlock;

        if (!RestGetRawTx(d.txid, deposit.dtx)) {
            LogPrintf("ERROR Enforcer client: REST raw-tx fetch failed for deposit %s (batch failed closed)\n", d.txid.ToString());
            return std::vector<SidechainDeposit>();
        }

        std::vector<uint256> vBlockTxid;
        if (!RestGetBlockTxids(d.hashBlock, vBlockTxid)) {
            LogPrintf("ERROR Enforcer client: REST block fetch failed for %s (batch failed closed)\n", d.hashBlock.ToString());
            return std::vector<SidechainDeposit>();
        }
        int nTx = -1;
        for (size_t j = 0; j < vBlockTxid.size(); j++) {
            if (vBlockTxid[j] == d.txid) { nTx = (int)j; break; }
        }
        if (nTx < 0) {
            LogPrintf("ERROR Enforcer client: deposit %s not found in block %s (batch failed closed)\n", d.txid.ToString(), d.hashBlock.ToString());
            return std::vector<SidechainDeposit>();
        }
        deposit.nTx = nTx;

        if (deposit.nBurnIndex >= deposit.dtx.vout.size()) {
            LogPrintf("%s: invalid deposit output index (batch failed closed)\n", __func__);
            return std::vector<SidechainDeposit>();
        }
        // Cumulative CTIP value at this deposit (the chassis subtracts the prior
        // CTIP itself). NOT the enforcer event's value_sats increment.
        deposit.amtUserPayout = deposit.dtx.vout[deposit.nBurnIndex].nValue;

        incoming.push_back(deposit);
    }

    // M6 payout treasury returns. When a withdrawal bundle succeeds, the M6
    // spends the CTIP and pays the remaining treasury to vout[0]
    // (bip300301_enforcer lib/types.rs into_m6). The legacy mainchain wallet
    // reports that change back as a "D" pseudo-deposit and the chassis CTIP
    // chain REQUIRES it - the miner refuses to build blocks over a gap - so
    // synthesize the equivalent entry from Succeeded withdrawal events. Like
    // the deposits above this re-emits every event each call; the miner's
    // HaveDepositNonAmount dedup is the backstop. Fail the batch closed on
    // any error.
    std::vector<L1WithdrawalEvent> vEvent;
    if (!ParseEnforcerWithdrawalEvents(result, vEvent)) {
        LogPrintf("ERROR Enforcer client: failed to parse withdrawal events (batch failed closed)\n");
        return std::vector<SidechainDeposit>();
    }

    // All deposit-event txids (not just new): used to exclude deposit txs
    // when locating the M6 inside its block.
    std::set<uint256> setDepositTxid;
    for (const EnfDep& d : vDep)
        setDepositTxid.insert(d.txid);

    // An M6 pays the sidechain treasury script at vout[0]:
    // OP_DRIVECHAIN(OP_NOP5) PUSH1(<sidechain#>) OP_TRUE
    const CScript scriptTreasury = CScript() << OP_NOP5
        << std::vector<unsigned char>{(unsigned char)THIS_SIDECHAIN} << OP_TRUE;

    for (const L1WithdrawalEvent& ev : vEvent) {
        if (ev.status != 'S')
            continue;

        if (ev.hashMainBlock.IsNull()) {
            LogPrintf("ERROR Enforcer client: Succeeded withdrawal event without block hash (batch failed closed)\n");
            return std::vector<SidechainDeposit>();
        }

        std::vector<uint256> vBlockTxid;
        if (!RestGetBlockTxids(ev.hashMainBlock, vBlockTxid)) {
            LogPrintf("ERROR Enforcer client: REST block fetch failed for %s (batch failed closed)\n", ev.hashMainBlock.ToString());
            return std::vector<SidechainDeposit>();
        }

        // Locate the M6: the single non-coinbase, non-deposit tx in the event
        // block paying the treasury script at vout[0]. Anything other than
        // exactly one match fails closed.
        int nFound = 0;
        int nTxM6 = -1;
        CMutableTransaction mtxM6;
        for (size_t j = 1; j < vBlockTxid.size(); j++) {
            if (setDepositTxid.count(vBlockTxid[j]))
                continue;

            CMutableTransaction mtx;
            if (!RestGetRawTx(vBlockTxid[j], mtx)) {
                LogPrintf("ERROR Enforcer client: REST raw-tx fetch failed for %s (batch failed closed)\n", vBlockTxid[j].ToString());
                return std::vector<SidechainDeposit>();
            }

            if (mtx.vout.empty() || mtx.vout[0].scriptPubKey != scriptTreasury)
                continue;

            nFound++;
            nTxM6 = (int)j;
            mtxM6 = mtx;
        }
        if (nFound != 1) {
            LogPrintf("ERROR Enforcer client: expected exactly 1 M6 in block %s, found %d (batch failed closed)\n", ev.hashMainBlock.ToString(), nFound);
            return std::vector<SidechainDeposit>();
        }

        SidechainDeposit deposit;
        deposit.nSidechain = THIS_SIDECHAIN;
        deposit.strDest = SIDECHAIN_WITHDRAWAL_BUNDLE_RETURN_DEST;
        deposit.dtx = mtxM6;
        deposit.nBurnIndex = 0; // into_m6 puts the treasury change at vout[0]
        deposit.nTx = nTxM6;
        deposit.hashMainchainBlock = ev.hashMainBlock;
        // Cumulative treasury remaining after the payout; the miner's delta
        // arithmetic clamps a "D" entry to 0 user payout itself (miner.cpp).
        deposit.amtUserPayout = mtxM6.vout[0].nValue;

        incoming.push_back(deposit);
    }

    // Deposits are oldest-first (seq ascending); the jsonrpc path reverses
    // because the RPC returns newest-first - we do not need to. Synthesized
    // "D" entries ride at the end: SortDeposits reconstructs true CTIP spend
    // order from the vin chain before the miner uses the batch.
    return incoming;
}

bool EnforcerL1Client::VerifyDeposit(const uint256& hashMainBlock, const uint256& txid, const int nTx)
{
    // Byte-identical to the jsonrpc verifydeposit: confirm the deposit tx sits
    // at index nTx of the named mainchain block (block.vtx[nTx].GetHash()==txid).
    // Fail closed if REST is unavailable or the index is out of range.
    if (gArgs.GetArg("-mainchainrest", DEFAULT_MAINCHAIN_REST).empty()) {
        LogUnimplemented("VerifyDeposit", "set -mainchainrest=<host:port>");
        return false;
    }

    std::vector<uint256> vTxid;
    if (!RestGetBlockTxids(hashMainBlock, vTxid))
        return false;

    if (nTx < 0 || (size_t)nTx >= vTxid.size())
        return false;

    return vTxid[nTx] == txid;
}

bool EnforcerL1Client::VerifyBMM(const uint256& hashMainBlock, const uint256& hashBMM, uint256& txid, uint32_t& nTime)
{
    std::string strRequest = "{\"block_hash\": {\"hex\": \"" + hashMainBlock.ToString() +
        "\"}, \"sidechain_id\": " + std::to_string(THIS_SIDECHAIN) + "}";

    UniValue result(UniValue::VOBJ);
    if (!CallValidator("GetBmmHStarCommitment", strRequest, result))
        return false;

    bool fBlockFound = false;
    bool fHaveCommitment = false;
    uint256 hashCommitment;
    if (!ParseEnforcerBmmCommitment(result, fBlockFound, fHaveCommitment, hashCommitment))
        return false;

    if (!fBlockFound || !fHaveCommitment || hashCommitment != hashBMM)
        return false;

    // The sidechain block header copies the mainchain block time
    std::vector<L1BlockHeader> vHeader;
    if (!GetHeaderInfos(hashMainBlock, 0, vHeader) || vHeader.empty())
        return false;

    nTime = vHeader.front().nTime;

    // The enforcer exposes the commitment itself, not the mainchain txid
    // carrying it; callers only log the txid.
    txid.SetNull();

    LogPrintf("Enforcer client found BMM for h*: %s\n", hashBMM.ToString());
    return true;
}

uint256 EnforcerL1Client::SendBMMRequest(const uint256& hashBMM, const uint256& hashBlockMain, int nHeight, CAmount amount)
{
    // WalletService/CreateBmmCriticalDataTransaction. Builds, funds (from the
    // enforcer wallet), signs and broadcasts the BMM request in one call.
    if (amount == CAmount(0))
        amount = DEFAULT_CRITICAL_DATA_AMOUNT;

    // Divergences from the JSON-RPC twin:
    //  - value_sats is an integer of SATS, not a ValueFromAmount decimal string.
    //  - critical_hash is ConsensusHex (internal byte order) - h* is a merkle
    //    root, so encode with ConsensusHexFromUint256, NOT ToString().
    //  - prev_bytes is the FULL mainchain tip hash (display order / ReverseHex);
    //    the enforcer hard-rejects anything but the current tip, so we do NOT
    //    truncate to the last 4 bytes the way the drivechain RPC does.
    std::string strRequest =
        "{\"sidechain_id\": " + std::to_string(THIS_SIDECHAIN) +
        ", \"value_sats\": " + std::to_string(amount) +
        ", \"height\": " + std::to_string(nHeight) +
        ", \"critical_hash\": {\"hex\": \"" + ConsensusHexFromUint256(hashBMM) + "\"}" +
        ", \"prev_bytes\": {\"hex\": \"" + hashBlockMain.ToString() + "\"}}";

    UniValue result(UniValue::VOBJ);
    if (!CallWallet("CreateBmmCriticalDataTransaction", strRequest, result)) {
        // Fails (non-zero grpcurl exit) on: stale prev_bytes (not the tip),
        // AlreadyExists for this tip, inactive sidechain, or unfunded wallet.
        // Null txid == "no request created", same as the JSON-RPC twin.
        return uint256();
    }

    std::string strTxid;
    if (!GetHexField(find_value(result, "txid"), strTxid))
        return uint256();

    uint256 txid = uint256S(strTxid);
    if (!txid.IsNull())
        LogPrintf("Enforcer client created BMM request. TXID: %s\n", txid.ToString());

    return txid;
}

bool EnforcerL1Client::GetCTIP(std::pair<uint256, uint32_t>& ctip)
{
    std::string strRequest = "{\"sidechain_number\": " + std::to_string(THIS_SIDECHAIN) + "}";

    UniValue result(UniValue::VOBJ);
    if (!CallValidator("GetCtip", strRequest, result))
        return false;

    uint256 txid;
    uint32_t n = 0;
    if (!ParseEnforcerCtip(result, txid, n))
        return false;

    ctip = std::make_pair(txid, n);
    return true;
}

bool EnforcerL1Client::GetAverageFees(int nBlocks, int nStartHeight, CAmount& nAverageFees)
{
    LogUnimplemented("GetAverageFees", "no enforcer equivalent; informational only");
    return false;
}

bool EnforcerL1Client::GetBlockCount(int& nBlocks)
{
    L1BlockHeader header;
    if (!GetChainTip(header))
        return false;

    nBlocks = header.nHeight;
    return true;
}

bool EnforcerL1Client::GetWorkScore(const uint256& hash, int& nWorkScore)
{
    // No enforcer equivalent: the enforcer surfaces discrete WithdrawalBundleEvents
    // (Submitted/Succeeded/Failed), not a running ACK workscore. GetWorkScore is
    // GUI-display only (qt/sidechainpage.cpp) - consensus/the miner do not use it -
    // so leaving it unavailable is harmless on a headless node.
    LogUnimplemented("GetWorkScore", "no enforcer workscore concept; GUI-only, not consensus");
    return false;
}

bool EnforcerL1Client::ListWithdrawalBundleStatus(std::vector<uint256>& vHashWithdrawalBundle)
{
    // Used by CreateWithdrawalBundleTx as a double-propose guard (don't create a
    // new bundle if one is already tracked on L1) - the caller only tests for
    // presence. NB the returned hashes are enforcer m6ids (blinded txids), not
    // chassis bundle hashes; do not match them against chassis hashes.
    std::vector<L1WithdrawalEvent> vEvents;
    if (!FetchWithdrawalEvents(vEvents))
        return false;

    for (const L1WithdrawalEvent& e : vEvents) {
        if (e.status == 'U' || e.status == 'S')
            vHashWithdrawalBundle.push_back(e.m6id);
    }
    return vHashWithdrawalBundle.size() > 0;
}

bool EnforcerL1Client::GetBlockHash(int nHeight, uint256& hashBlock)
{
    // The enforcer indexes by block hash, not height: walk back from the tip
    // in batched ancestor chunks until the requested height. Steady-state
    // callers ask for heights at or near the tip; deep walks only happen on
    // a cold header-cache sync.
    L1BlockHeader tip;
    if (!GetChainTip(tip))
        return false;

    if (nHeight < 0 || nHeight > tip.nHeight)
        return false;

    if (nHeight == tip.nHeight) {
        hashBlock = tip.hashBlock;
        return true;
    }

    uint256 hashCursor = tip.hashBlock;
    int nCursor = tip.nHeight;
    while (nCursor > nHeight) {
        uint32_t nWant = std::min(nCursor - nHeight, 1000);

        std::vector<L1BlockHeader> vHeader;
        if (!GetHeaderInfos(hashCursor, nWant, vHeader))
            return false;

        // Newest-first: [0] is the cursor block itself
        for (const L1BlockHeader& header : vHeader) {
            if (header.nHeight == nHeight) {
                hashBlock = header.hashBlock;
                return true;
            }
        }

        // Continue from the oldest returned header; require progress
        const L1BlockHeader& oldest = vHeader.back();
        if (oldest.nHeight >= nCursor)
            return false;

        hashCursor = oldest.hashBlock;
        nCursor = oldest.nHeight;
    }

    return false;
}

bool EnforcerL1Client::GetAncestorHashes(const uint256& hashBlock, int nHeight, uint32_t nMax, std::vector<uint256>& vHash)
{
    // The enforcer indexes by hash, so a batch of ancestors is a single call:
    // ask for the cursor block plus its (nMax - 1) ancestors.
    vHash.clear();
    if (nMax == 0)
        return true;

    std::vector<L1BlockHeader> vHeader;
    if (!GetHeaderInfos(hashBlock, nMax - 1, vHeader))
        return false;

    // Newest-first, [0] == hashBlock. Stop at genesis rather than trusting the
    // caller's count.
    for (const L1BlockHeader& header : vHeader) {
        vHash.push_back(header.hashBlock);
        if (header.nHeight == 0)
            break;
    }

    return !vHash.empty();
}

bool EnforcerL1Client::FetchWithdrawalEvents(std::vector<L1WithdrawalEvent>& vEvents)
{
    L1BlockHeader tip;
    if (!GetChainTip(tip))
        return false;

    std::string strRequest = "{\"sidechain_id\": " + std::to_string(THIS_SIDECHAIN) +
        ", \"end_block_hash\": {\"hex\": \"" + tip.hashBlock.ToString() + "\"}}";

    UniValue result(UniValue::VOBJ);
    if (!CallValidator("GetTwoWayPegData", strRequest, result))
        return false;

    return ParseEnforcerWithdrawalEvents(result, vEvents);
}

// Map a chassis bundle hash (the bundle txid, dummy input included - the
// value committed in sidechain blocks and passed to the status queries) to
// the enforcer's m6id: the txid of the SAME bundle with its inputs stripped.
// The enforcer's compute_m6id is compute_txid() of the zero-input BlindedM6
// (bip300301_enforcer lib/types.rs), and a txid is the hash of the
// no-witness serialization on both sides, so stripping vin is the whole map.
static bool BlindedM6IdForBundle(const uint256& hashBundle, uint256& m6id)
{
    if (!psidechaintree)
        return false;

    SidechainWithdrawalBundle bundle;
    if (!psidechaintree->GetWithdrawalBundle(hashBundle, bundle))
        return false;

    CMutableTransaction mtx(bundle.tx);
    mtx.vin.clear();
    m6id = CTransaction(mtx).GetHash();
    return true;
}

bool EnforcerL1Client::HaveSpentWithdrawalBundle(const uint256& hash)
{
    // "Spent" == the bundle's M6 payout succeeded on the mainchain. Translate
    // the chassis bundle hash to the enforcer m6id before matching events; an
    // unknown bundle fails closed.
    uint256 m6id;
    if (!BlindedM6IdForBundle(hash, m6id))
        return false;

    std::vector<L1WithdrawalEvent> vEvents;
    if (!FetchWithdrawalEvents(vEvents))
        return false;

    for (const L1WithdrawalEvent& e : vEvents) {
        if (e.status == 'S' && e.m6id == m6id)
            return true;
    }
    return false;
}

bool EnforcerL1Client::HaveFailedWithdrawalBundle(const uint256& hash)
{
    // Same chassis-hash -> m6id translation as HaveSpentWithdrawalBundle.
    uint256 m6id;
    if (!BlindedM6IdForBundle(hash, m6id))
        return false;

    std::vector<L1WithdrawalEvent> vEvents;
    if (!FetchWithdrawalEvents(vEvents))
        return false;

    for (const L1WithdrawalEvent& e : vEvents) {
        if (e.status == 'F' && e.m6id == m6id)
            return true;
    }
    return false;
}

//
// Transport selection
//

bool IsValidL1Transport(const std::string& strTransport)
{
    return strTransport == "jsonrpc" || strTransport == "enforcer";
}

const std::string& DefaultMainchainTransport()
{
    static const std::string jsonrpc = "jsonrpc";
    static const std::string enforcer = "enforcer";
    return Params().NetworkIDString() == CBaseChainParams::REGTEST ? jsonrpc : enforcer;
}

L1Transport GetL1Transport()
{
    static const L1Transport transport =
        gArgs.GetArg("-mainchaintransport", DefaultMainchainTransport()) == "enforcer" ?
            L1Transport::ENFORCER : L1Transport::JSONRPC;
    return transport;
}

L1Client& GetL1Client()
{
    static JsonRpcL1Client clientJsonRpc;
    static EnforcerL1Client clientEnforcer;

    if (GetL1Transport() == L1Transport::ENFORCER)
        return clientEnforcer;

    return clientJsonRpc;
}

//
// JsonRpcL1Client (bodies moved verbatim from SidechainClient)
//

bool JsonRpcL1Client::BroadcastWithdrawalBundle(const std::string& hex)
{
    // JSON for sending the WithdrawalBundle to mainchain via HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"receivewithdrawalbundle\", \"params\": ");
    json.append("[");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    json.append(",\"");
    json.append(hex);
    json.append("\"] }");

    // TODO Read result
    // the mainchain will return the txid if WithdrawalBundle has been received
    boost::property_tree::ptree ptree;
    return SendRequestToMainchain(json, ptree);
}

// TODO return bool & state / fail string
std::vector<SidechainDeposit> JsonRpcL1Client::UpdateDeposits(const uint256& hashLastDeposit, uint32_t nLastBurnIndex)
{
    // List of deposits in sidechain format for DB
    std::vector<SidechainDeposit> incoming;

    // JSON for requesting sidechain deposits via mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"listsidechaindeposits\", \"params\": ");
    json.append("[");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    if (hashLastDeposit.IsNull()) {
        json.append("] }");
    } else {
        json.append(",");
        json.append("\"");
        json.append(hashLastDeposit.ToString());
        json.append("\",");
        json.append(UniValue(uint64_t(nLastBurnIndex)).write());
        json.append("] }");
    }

    // Try to request deposits from mainchain
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to request new deposits\n");
        return incoming;
    }

    // Process deposits
    BOOST_FOREACH(boost::property_tree::ptree::value_type &value, ptree.get_child("result")) {
        // Looping through list of deposits
        SidechainDeposit deposit;
        BOOST_FOREACH(boost::property_tree::ptree::value_type &v, value.second.get_child("")) {
            // Looping through this deposit's members
            if (v.first == "nsidechain") {
                // Read sidechain number
                std::string data = v.second.data();
                if (!data.length())
                    continue;
                uint8_t nSidechain = std::stoi(data);
                if (nSidechain != THIS_SIDECHAIN)
                    continue;

                deposit.nSidechain = nSidechain;
            }
            else
            if (v.first == "strdest") {
                // Read destination string
                std::string strDest = v.second.data();
                if (strDest.empty())
                    continue;

                deposit.strDest = strDest;
            }
            else
            if (v.first == "txhex") {
                // Read deposit transaction hex
                std::string data = v.second.data();
                if (!data.length())
                    continue;
                if (!IsHex(data))
                    continue;
                if (!DecodeHexTx(deposit.dtx, data))
                    continue;
            }
            else
            if (v.first == "nburnindex") {
                // Read deposit output index
                std::string data = v.second.data();
                if (!data.length())
                    continue;

                deposit.nBurnIndex = std::stoi(data);
            }
            else
            if (v.first == "ntx") {
                // Read mainchain block hash
                std::string data = v.second.data();
                if (!data.length())
                    continue;

                deposit.nTx = std::stoi(data);
            }
            else
            if (v.first == "hashblock") {
                // Read mainchain block hash
                std::string data = v.second.data();
                if (!data.length())
                    continue;

                deposit.hashMainchainBlock = uint256S(data);
            }
        }

        if (deposit.nBurnIndex >= deposit.dtx.vout.size()) {
            LogPrintf("%s: Error invalid deposit output index!\n", __func__);
            continue;
        }

        // Get the user payout amount from the deposit output. At this point the
        // amount is the total CTIP, and the real payout will be calculated
        // later.
        deposit.amtUserPayout = deposit.dtx.vout[deposit.nBurnIndex].nValue;

        // Add this deposit to the list
        incoming.push_back(deposit);
    }
    // LogPrintf("Sidechain client received %d deposits\n", incoming.size());

    // The deposits are sent in reverse order. Putting the deposits back in
    // order should make sorting faster.
    std::reverse(incoming.begin(), incoming.end());

    // return valid (in terms of format) deposits in sidechain format
    return incoming;
}

bool JsonRpcL1Client::VerifyDeposit(const uint256& hashMainBlock, const uint256& txid, const int nTx)
{
    // JSON for requesting deposit verification via mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"verifydeposit\", \"params\": ");
    json.append("[\"");
    json.append(hashMainBlock.ToString());
    json.append("\",\"");
    json.append(txid.ToString());
    json.append("\",");
    json.append(UniValue(nTx).write());
    json.append("] }");

    // Ask mainchain node to verify deposit
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        // Can be enabled for debug -- too noisy
        // LogPrintf("ERROR Sidechain client failed to verify deposit!\n");
        return false;
    }

    // Process result
    uint256 txidRet = uint256S(ptree.get("result", ""));
    return (txid == txidRet);
}

bool JsonRpcL1Client::VerifyBMM(const uint256& hashMainBlock, const uint256& hashBMM, uint256& txid, uint32_t& nTime)
{
    // JSON for requesting BMM proof via mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"verifybmm\", \"params\": ");
    json.append("[\"");
    json.append(hashMainBlock.ToString());
    json.append("\",\"");
    json.append(hashBMM.ToString());
    json.append("\",");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    json.append("] }");

    // Try to request BMM proof from mainchain
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        // Can be enabled for debug -- too noisy
        // LogPrintf("ERROR Sidechain client failed to request BMM proof\n");
        return false;
    }

    // Process result
    bool fFoundTx = false;
    bool fFoundTime = false;
    BOOST_FOREACH(boost::property_tree::ptree::value_type &value, ptree.get_child("result")) {
        BOOST_FOREACH(boost::property_tree::ptree::value_type &v, value.second.get_child("")) {
            if (v.first == "txid") {
                // Read BMM txid
                std::string data = v.second.data();
                if (!data.length())
                    continue;

                txid = uint256S(data);
                fFoundTx = true;
            }
            else
            if (v.first == "time") {
                // Read mainchain block time
                std::string data = v.second.data();
                if (!data.length())
                    continue;

                nTime = std::stoi(data);
                fFoundTime = true;
            }
        }
    }

    if (fFoundTx && fFoundTime) {
        LogPrintf("Sidechain client found BMM for h*: %s\n", hashBMM.ToString());
        return true;
    } else {
        // Can be enabled for debug -- too noisy
        // LogPrintf("Sidechain client found no BMM.\n");
        return false;
    }
}

uint256 JsonRpcL1Client::SendBMMRequest(const uint256& hashCritical, const uint256& hashBlockMain, int nHeight, CAmount amount)
{
    uint256 txid = uint256();
    std::string strPrevHash = hashBlockMain.ToString();

    if (amount == CAmount(0))
        amount = DEFAULT_CRITICAL_DATA_AMOUNT;

    // JSON for sending critical data request to mainchain via mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"createbmmcriticaldatatx\", \"params\": ");
    json.append("[\"");
    json.append(ValueFromAmount(amount).write());
    json.append("\",");
    json.append(UniValue(nHeight).write());
    json.append(",\"");
    json.append(hashCritical.ToString());
    json.append("\",");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    json.append(",\"");
    json.append(strPrevHash.substr(strPrevHash.size() - 8, strPrevHash.size() - 1));
    json.append("\"");
    json.append("] }");

    // Try to send critical data request to mainchain
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to create BMM request on mainchain!\n");
        return txid; // TODO
    }

    // Process result
    BOOST_FOREACH(boost::property_tree::ptree::value_type &value, ptree.get_child("result")) {
        BOOST_FOREACH(boost::property_tree::ptree::value_type &v, value.second.get_child("")) {
            // Looping through members
            if (v.first == "txid") {
                // Read txid
                std::string data = v.second.data();
                if (!data.length())
                    continue;

                txid = uint256S(data);
            }
        }
    }
    if (!txid.IsNull())
        LogPrintf("Sidechain client created critical data request. TXID: %s\n", txid.ToString());

    return txid;
}

bool JsonRpcL1Client::GetCTIP(std::pair<uint256, uint32_t>& ctip)
{
    // JSON for requesting sidechain CTIP via mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"listsidechainctip\", \"params\": ");
    json.append("[");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    json.append("] }");

    // Try to request CTIP from mainchain
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        // TODO LogPrintf("ERROR Sidechain client failed to request CTIP\n");
        return false;
    }

    // Process CTIP
    uint256 txid;
    uint32_t n = 0;
    BOOST_FOREACH(boost::property_tree::ptree::value_type &value, ptree.get_child("result")) {
        if (value.first == "n") {
            // Read n
            std::string data = value.second.data();
            if (!data.length())
                continue;
            n = std::stoi(data);
        }
        else
        if (value.first == "txid") {
            // Read TXID
            std::string data = value.second.data();
            if (!data.length())
                continue;

            txid = uint256S(data);
        }
    }
    // TODO LogPrintf("Sidechain client received CTIP\n");

    ctip = std::make_pair(txid, n);

    return true;
}

bool JsonRpcL1Client::GetAverageFees(int nBlocks, int nStartHeight, CAmount& nAverageFee)
{
    // JSON for 'getaveragefees' mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"getaveragefee\", \"params\": ");
    json.append("[");
    json.append(UniValue(nBlocks).write());
    json.append(",");
    json.append(UniValue(nStartHeight).write());
    json.append("]");
    json.append("}");

    // Try to request average fees from mainchain
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to request average fees\n");
        return false;
    }

    // Process result
    BOOST_FOREACH(boost::property_tree::ptree::value_type &value, ptree.get_child("result")) {
        // Looping through members
        if (value.first == "feeaverage") {
            // Read
            std::string data = value.second.data();
            if (!data.length()) {
                LogPrintf("ERROR Sidechain client received invalid data\n");
                return false;
            }

            if (ParseMoney(data, nAverageFee)) {
                LogPrintf("Sidechain client received average mainchain fee: %d.\n", nAverageFee);
                return true;
            }
        }
    }
    return false;
}

bool JsonRpcL1Client::GetBlockCount(int& nBlocks)
{
    // JSON for 'getblockcount' mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"getblockcount\", \"params\": ");
    json.append("[] }");

    // Try to request mainchain block count
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to request block count\n");
        return false;
    }

    // Process result
    nBlocks = ptree.get("result", 0);

    return nBlocks >= 0;
}

bool JsonRpcL1Client::GetWorkScore(const uint256& hash, int& nWorkScore)
{
    // JSON for 'getworkscore' mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"getworkscore\", \"params\": ");
    json.append("[");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    json.append(",");
    json.append("\"");
    json.append(hash.ToString());
    json.append("\"");
    json.append("] }");

    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to request workscore\n");
        return false;
    }

    // Process result, note that starting workscore on mainchain is 1
    nWorkScore = ptree.get("result", -1);

    return nWorkScore >= 0;
}

bool JsonRpcL1Client::ListWithdrawalBundleStatus(std::vector<uint256>& vHashWithdrawalBundle)
{
    // TODO for now this function is only being used to see if there are any
    // WithdrawalBundle(s) for nSidechain. The rest of the results could be useful for the
    // GUI though.

    // JSON for 'listwithdrawalstatus' mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"listwithdrawalstatus\", \"params\": ");
    json.append("[");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    json.append("] }");

    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to request WithdrawalBundle status\n");
        return false;
    }

    // Process result
    BOOST_FOREACH(boost::property_tree::ptree::value_type &value, ptree.get_child("result")) {
        BOOST_FOREACH(boost::property_tree::ptree::value_type &v, value.second.get_child("")) {
            // Looping through members
            if (v.first == "hash") {
                // Read txid
                std::string data = v.second.data();
                if (!data.length())
                    continue;

                uint256 hash = uint256S(data);
                if (!hash.IsNull())
                    vHashWithdrawalBundle.push_back(hash);
            }
        }
    }

    return vHashWithdrawalBundle.size() > 0;
}

bool JsonRpcL1Client::GetBlockHash(int nHeight, uint256& hashBlock)
{
    // JSON for 'getblockhash' mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"getblockhash\", \"params\": ");
    json.append("[");
    json.append(UniValue(nHeight).write());
    json.append("] }");

    // Try to request mainchain block hash
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to request block hash!\n");
        return false;
    }

    std::string strHash = ptree.get("result", "");
    hashBlock = uint256S(strHash);

    return (!hashBlock.IsNull());
}

bool JsonRpcL1Client::GetAncestorHashes(const uint256& hashBlock, int nHeight, uint32_t nMax, std::vector<uint256>& vHash)
{
    // The JSON-RPC mainchain indexes by height, so each hash is a direct
    // lookup: walk heights down from the cursor. Unchanged from the historical
    // per-block behaviour (getblockhash is O(1) on this transport).
    vHash.clear();
    if (nMax == 0)
        return true;

    // The cursor block's own hash is already known - do not re-request it.
    vHash.push_back(hashBlock);

    for (uint32_t i = 1; i < nMax; i++) {
        const int nWant = nHeight - (int)i;
        if (nWant < 0)
            break;

        uint256 hash;
        if (!GetBlockHash(nWant, hash))
            return false;

        vHash.push_back(hash);
    }

    return true;
}

bool JsonRpcL1Client::HaveSpentWithdrawalBundle(const uint256& hash)
{
    // JSON for 'havespentwithdrawalbundle' mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"havespentwithdrawal\", \"params\": ");
    json.append("[");
    json.append("\"");
    json.append(hash.ToString());
    json.append("\"");
    json.append(",");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    json.append("] }");

    // Try to request mainchain block hash
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to request spent WithdrawalBundle!\n");
        return false;
    }

    bool fSpent = ptree.get("result", false);

    return fSpent;
}

bool JsonRpcL1Client::HaveFailedWithdrawalBundle(const uint256& hash)
{
    // JSON for 'havefailedwithdrawalbundle' mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"havefailedwithdrawal\", \"params\": ");
    json.append("[");
    json.append("\"");
    json.append(hash.ToString());
    json.append("\"");
    json.append(",");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    json.append("] }");

    // Try to request mainchain block hash
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to request failed WithdrawalBundle!\n");
        return false;
    }

    bool fFailed = ptree.get("result", false);

    return fFailed;
}

bool JsonRpcL1Client::SendRequestToMainchain(const std::string& json, boost::property_tree::ptree &ptree)
{
    // Format user:pass for authentication
    std::string auth = gArgs.GetArg("-rpcuser", "") + ":" + gArgs.GetArg("-rpcpassword", "");
    if (auth == ":")
        return false;

    // Mainnet RPC = 8332
    // Testnet RPC = 18332
    // Regtest RPC = 18443
    //
    bool fRegtest = gArgs.GetBoolArg("-regtest", false);
    int port = fRegtest ? 18443 : 8332;

    try {
        // Setup BOOST ASIO for a synchronus call to the mainchain
        boost::asio::io_service io_service;
        tcp::resolver resolver(io_service);
        tcp::resolver::query query("127.0.0.1", std::to_string(port));
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
        tcp::resolver::iterator end;

        tcp::socket socket(io_service);
        boost::system::error_code error = boost::asio::error::host_not_found;

        // Try to connect
        while (error && endpoint_iterator != end)
        {
          socket.close();
          socket.connect(*endpoint_iterator++, error);
        }

        if (error) throw boost::system::system_error(error);

        // HTTP request (package the json for sending)
        boost::asio::streambuf output;
        std::ostream os(&output);
        os << "POST / HTTP/1.1\n";
        os << "Host: 127.0.0.1\n";
        os << "Content-Type: application/json\n";
        os << "Authorization: Basic " << EncodeBase64(auth) << std::endl;
        os << "Connection: close\n";
        os << "Content-Length: " << json.size() << "\n\n";
        os << json;

        // Send the request
        boost::asio::write(socket, output);

        // Read the reponse
        std::string data;
        for (;;)
        {
            boost::array<char, 4096> buf;

            // Read until end of file (socket closed)
            boost::system::error_code e;
            size_t sz = socket.read_some(boost::asio::buffer(buf), e);

            data.insert(data.size(), buf.data(), sz);

            if (e == boost::asio::error::eof)
                break; // socket closed
            else if (e)
                throw boost::system::system_error(e);
        }

        std::stringstream ss;
        ss << data;

        // Get response code
        ss.ignore(std::numeric_limits<std::streamsize>::max(), ' ');
        int code;
        ss >> code;

        // Check response code
        if (code != 200)
            return false;

        // Skip the rest of the header
        for (size_t i = 0; i < 5; i++)
            ss.ignore(std::numeric_limits<std::streamsize>::max(), '\r');

        // Parse json response;
        std::string JSON;
        ss >> JSON;
        std::stringstream jss;
        jss << JSON;
        boost::property_tree::json_parser::read_json(jss, ptree);
    } catch (std::exception &exception) {
        LogPrintf("ERROR Sidechain client (sendRequestToMainchain): %s\n", exception.what());
        return false;
    }
    return true;
}
