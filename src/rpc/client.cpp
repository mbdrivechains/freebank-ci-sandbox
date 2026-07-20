// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/client.h>
#include <rpc/protocol.h>
#include <util.h>

#include <set>
#include <stdint.h>

class CRPCConvertParam
{
public:
    std::string methodName; //!< method whose params want conversion
    int paramIdx;           //!< 0-based idx of param to convert
    std::string paramName;  //!< parameter name
};

/**
 * Specify a (method, idx, name) here if the argument is a non-string RPC
 * argument and needs to be converted from JSON.
 *
 * @note Parameter indexes start from 0.
 */
static const CRPCConvertParam vRPCConvertParams[] =
{
    { "setmocktime", 0, "timestamp" },
    { "getnetworkhashps", 0, "nblocks" },
    { "getnetworkhashps", 1, "height" },
    { "sendtoaddress", 1, "amount" },
    { "sendtoaddress", 4, "subtractfeefromamount" },
    { "sendtoaddress", 5 , "replaceable" },
    { "sendtoaddress", 6 , "conf_target" },
    { "settxfee", 0, "amount" },
    { "getreceivedbyaddress", 1, "minconf" },
    { "getreceivedbyaccount", 1, "minconf" },
    { "listreceivedbyaddress", 0, "minconf" },
    { "listreceivedbyaddress", 1, "include_empty" },
    { "listreceivedbyaddress", 2, "include_watchonly" },
    { "listreceivedbyaccount", 0, "minconf" },
    { "listreceivedbyaccount", 1, "include_empty" },
    { "listreceivedbyaccount", 2, "include_watchonly" },
    { "getbalance", 1, "minconf" },
    { "getbalance", 2, "include_watchonly" },
    { "getblockhash", 0, "height" },
    { "waitforblockheight", 0, "height" },
    { "waitforblockheight", 1, "timeout" },
    { "waitforblock", 1, "timeout" },
    { "waitfornewblock", 0, "timeout" },
    { "move", 2, "amount" },
    { "move", 3, "minconf" },
    { "sendfrom", 2, "amount" },
    { "sendfrom", 3, "minconf" },
    { "listtransactions", 1, "count" },
    { "listtransactions", 2, "skip" },
    { "listtransactions", 3, "include_watchonly" },
    { "listaccounts", 0, "minconf" },
    { "listaccounts", 1, "include_watchonly" },
    { "walletpassphrase", 1, "timeout" },
    { "listsinceblock", 1, "target_confirmations" },
    { "listsinceblock", 2, "include_watchonly" },
    { "listsinceblock", 3, "include_removed" },
    { "sendmany", 1, "amounts" },
    { "sendmany", 2, "minconf" },
    { "sendmany", 4, "subtractfeefrom" },
    { "sendmany", 5 , "replaceable" },
    { "sendmany", 6 , "conf_target" },
    { "addmultisigaddress", 0, "nrequired" },
    { "addmultisigaddress", 1, "keys" },
    { "createmultisig", 0, "nrequired" },
    { "createmultisig", 1, "keys" },
    { "listunspent", 0, "minconf" },
    { "listunspent", 1, "maxconf" },
    { "listunspent", 2, "addresses" },
    { "listunspent", 3, "include_unsafe" },
    { "listunspent", 4, "query_options" },
    { "getblock", 1, "verbosity" },
    { "getblock", 1, "verbose" },
    { "getblockheader", 1, "verbose" },
    { "getchaintxstats", 0, "nblocks" },
    { "getchainheaders", 0, "nheaders" },
    { "gettransaction", 1, "include_watchonly" },
    { "getrawtransaction", 1, "verbose" },
    { "createrawtransaction", 0, "inputs" },
    { "createrawtransaction", 1, "outputs" },
    { "createrawtransaction", 2, "locktime" },
    { "createrawtransaction", 3, "replaceable" },
    { "decoderawtransaction", 1, "iswitness" },
    { "signrawtransaction", 1, "prevtxs" },
    { "signrawtransaction", 2, "privkeys" },
    { "signrawtransactionwithkey", 1, "privkeys" },
    { "signrawtransactionwithkey", 2, "prevtxs" },
    { "signrawtransactionwithwallet", 1, "prevtxs" },
    { "sendrawtransaction", 1, "allowhighfees" },
    { "combinerawtransaction", 0, "txs" },
    { "fundrawtransaction", 1, "options" },
    { "fundrawtransaction", 2, "iswitness" },
    { "gettxout", 1, "n" },
    { "gettxout", 2, "include_mempool" },
    { "gettxoutproof", 0, "txids" },
    { "lockunspent", 0, "unlock" },
    { "lockunspent", 1, "transactions" },
    { "importprivkey", 2, "rescan" },
    { "importaddress", 2, "rescan" },
    { "importaddress", 3, "p2sh" },
    { "importpubkey", 2, "rescan" },
    { "importmulti", 0, "requests" },
    { "importmulti", 1, "options" },
    { "verifychain", 0, "checklevel" },
    { "verifychain", 1, "nblocks" },
    { "pruneblockchain", 0, "height" },
    { "keypoolrefill", 0, "newsize" },
    { "getrawmempool", 0, "verbose" },
    { "estimatesmartfee", 0, "conf_target" },
    { "estimaterawfee", 0, "conf_target" },
    { "estimaterawfee", 1, "threshold" },
    { "prioritisetransaction", 1, "dummy" },
    { "prioritisetransaction", 2, "fee_delta" },
    { "setban", 2, "bantime" },
    { "setban", 3, "absolute" },
    { "setnetworkactive", 0, "state" },
    { "getmempoolancestors", 1, "verbose" },
    { "getmempooldescendants", 1, "verbose" },
    { "bumpfee", 1, "options" },
    { "logging", 0, "include" },
    { "logging", 1, "exclude" },
    { "disconnectnode", 1, "nodeid" },
    { "addwitnessaddress", 1, "p2sh" },
    // Echo with conversion (For testing only)
    { "echojson", 0, "arg0" },
    { "echojson", 1, "arg1" },
    { "echojson", 2, "arg2" },
    { "echojson", 3, "arg3" },
    { "echojson", 4, "arg4" },
    { "echojson", 5, "arg5" },
    { "echojson", 6, "arg6" },
    { "echojson", 7, "arg7" },
    { "echojson", 8, "arg8" },
    { "echojson", 9, "arg9" },
    { "rescanblockchain", 0, "start_height"},
    { "rescanblockchain", 1, "stop_height"},
    // Drivechain
    { "createwithdrawal", 2, "namount"},
    { "createwithdrawal", 3, "nfee"},
    { "createwithdrawal", 4, "nmainchainfee"},
    { "getaveragemainchainfees", 0, "blockcount" },
    { "getaveragemainchainfees", 1, "startheight" },
    { "refreshbmm", 0, "amount" },
    { "refreshbmm", 1, "createnew" },
    { "getmainchainblockhash", 0, "height" },
    // BitAssets
    { "createasset", 3, "fee" },
    { "createasset", 4, "supply" },
    { "transferasset", 3, "amount" },
    { "issuebill", 1, "amount" },
    { "issuebill", 2, "escrow" },
    { "issuebill", 3, "maturityheight" },
    { "issuebill", 4, "graceblocks" },
    { "issuebill", 5, "fee" },
    { "endorsebill", 0, "id" },
    { "endorsebill", 2, "fee" },
    { "retirebill", 0, "id" },
    { "retirebill", 1, "fee" },
    { "claimbillescrow", 0, "id" },
    { "claimbillescrow", 1, "fee" },
    { "getbill", 0, "id" },
    { "mintnote", 0, "id" },
    { "mintnote", 1, "units" },
    { "mintnote", 2, "fee" },
    { "transfernote", 0, "id" },
    { "transfernote", 1, "units" },
    { "transfernote", 2, "fee" },
    { "redeemnote", 0, "id" },
    { "redeemnote", 1, "units" },
    { "redeemnote", 2, "fee" },
    { "demandnote", 0, "id" },
    { "demandnote", 1, "units" },
    { "demandnote", 2, "fee" },
    { "claimnote", 0, "id" },
    { "claimnote", 1, "units" },
    { "claimnote", 2, "fee" },
    { "originatedeposit", 0, "id" },
    { "originatedeposit", 1, "principal" },
    { "originatedeposit", 2, "ratebps" },
    { "originatedeposit", 3, "maturity" },
    { "originatedeposit", 4, "fee" },
    { "createpool", 0, "id" },
    { "createpool", 1, "noteunits" },
    { "createpool", 2, "btxsats" },
    { "createpool", 3, "feebps" },
    { "createpool", 4, "fee" },
    { "addpoolliquidity", 0, "id" },
    { "addpoolliquidity", 1, "noteunits" },
    { "addpoolliquidity", 2, "btxsats" },
    { "addpoolliquidity", 3, "fee" },
    { "removepoolliquidity", 0, "id" },
    { "removepoolliquidity", 1, "lpunits" },
    { "removepoolliquidity", 2, "fee" },
    { "retirepool", 0, "id" },
    { "retirepool", 1, "fee" },
    { "swapnote", 0, "id" },
    { "swapnote", 2, "amountin" },
    { "swapnote", 3, "minout" },
    { "swapnote", 4, "fee" },
    { "getpool", 0, "id" },
    { "transferdeposit", 0, "id" },
    { "transferdeposit", 1, "principal" },
    { "transferdeposit", 2, "fee" },
    { "withdrawdeposit", 0, "id" },
    { "withdrawdeposit", 1, "principal" },
    { "withdrawdeposit", 2, "fee" },
    { "claimdeposit", 0, "id" },
    { "claimdeposit", 1, "principal" },
    { "claimdeposit", 2, "fee" },
    { "registerhouse", 0, "tier" },
    { "registerhouse", 1, "threshold" },
    { "registerhouse", 3, "denommg" },
    { "registerhouse", 4, "pledges" },
    { "registerhouse", 5, "fee" },
    { "topuphouse", 0, "id" },
    { "topuphouse", 1, "partner" },
    { "topuphouse", 2, "amount" },
    { "topuphouse", 3, "fee" },
    { "admitpartner", 0, "id" },
    { "admitpartner", 1, "pledge" },
    { "admitpartner", 2, "fee" },
    { "exitpartner", 0, "id" },
    { "exitpartner", 1, "partner" },
    { "exitpartner", 2, "fee" },
    { "winddownhouse", 0, "id" },
    { "winddownhouse", 1, "fee" },
    { "attesthouse", 0, "id" },
    { "attesthouse", 1, "fee" },
    { "deferhouse", 0, "id" },
    { "deferhouse", 1, "fee" },
    { "releasereserves", 0, "id" },
    { "releasereserves", 1, "fee" },
    { "renewdeferral", 0, "id" },
    { "renewdeferral", 1, "fee" },
    { "reclaimpledge", 0, "id" },
    { "reclaimpledge", 1, "partner" },
    { "reclaimpledge", 2, "fee" },
    { "gethouse", 0, "id" },
};

class CRPCConvertTable
{
private:
    std::set<std::pair<std::string, int>> members;
    std::set<std::pair<std::string, std::string>> membersByName;

public:
    CRPCConvertTable();

    bool convert(const std::string& method, int idx) {
        return (members.count(std::make_pair(method, idx)) > 0);
    }
    bool convert(const std::string& method, const std::string& name) {
        return (membersByName.count(std::make_pair(method, name)) > 0);
    }
};

CRPCConvertTable::CRPCConvertTable()
{
    const unsigned int n_elem =
        (sizeof(vRPCConvertParams) / sizeof(vRPCConvertParams[0]));

    for (unsigned int i = 0; i < n_elem; i++) {
        members.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                      vRPCConvertParams[i].paramIdx));
        membersByName.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                            vRPCConvertParams[i].paramName));
    }
}

static CRPCConvertTable rpcCvtTable;

/** Non-RFC4627 JSON parser, accepts internal values (such as numbers, true, false, null)
 * as well as objects and arrays.
 */
UniValue ParseNonRFCJSONValue(const std::string& strVal)
{
    UniValue jVal;
    if (!jVal.read(std::string("[")+strVal+std::string("]")) ||
        !jVal.isArray() || jVal.size()!=1)
        throw std::runtime_error(std::string("Error parsing JSON:")+strVal);
    return jVal[0];
}

UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VARR);

    for (unsigned int idx = 0; idx < strParams.size(); idx++) {
        const std::string& strVal = strParams[idx];

        if (!rpcCvtTable.convert(strMethod, idx)) {
            // insert string value directly
            params.push_back(strVal);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.push_back(ParseNonRFCJSONValue(strVal));
        }
    }

    return params;
}

UniValue RPCConvertNamedValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VOBJ);

    for (const std::string &s: strParams) {
        size_t pos = s.find('=');
        if (pos == std::string::npos) {
            throw(std::runtime_error("No '=' in named argument '"+s+"', this needs to be present for every argument (even if it is empty)"));
        }

        std::string name = s.substr(0, pos);
        std::string value = s.substr(pos+1);

        if (!rpcCvtTable.convert(strMethod, name)) {
            // insert string value directly
            params.pushKV(name, value);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.pushKV(name, ParseNonRFCJSONValue(value));
        }
    }

    return params;
}
