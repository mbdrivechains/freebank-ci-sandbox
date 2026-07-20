// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sidechainclient.h>

#include <bmmcache.h>
#include <chainparams.h>
#include <l1client.h>
#include <miner.h>
#include <sidechain.h>

#include <string>

SidechainClient::SidechainClient()
{

}

//
// Mainchain queries delegate to the L1Client backend selected by
// -mainchaintransport (jsonrpc | enforcer). BMM orchestration (RefreshBMM /
// CreateBMMBlock / SubmitBMMBlock) stays here - it is sidechain-node logic,
// not mainchain I/O.
//

bool SidechainClient::BroadcastWithdrawalBundle(const std::string& hex)
{
    return GetL1Client().BroadcastWithdrawalBundle(hex);
}

std::vector<SidechainDeposit> SidechainClient::UpdateDeposits(const uint256& hashLastDeposit, uint32_t nLastBurnIndex)
{
    return GetL1Client().UpdateDeposits(hashLastDeposit, nLastBurnIndex);
}

bool SidechainClient::VerifyDeposit(const uint256& hashMainBlock, const uint256& txid, const int nTx)
{
    return GetL1Client().VerifyDeposit(hashMainBlock, txid, nTx);
}

bool SidechainClient::VerifyBMM(const uint256& hashMainBlock, const uint256& hashBMM, uint256& txid, uint32_t& nTime)
{
    return GetL1Client().VerifyBMM(hashMainBlock, hashBMM, txid, nTime);
}

uint256 SidechainClient::SendBMMRequest(const uint256& hashBMM, const uint256& hashBlockMain, int nHeight, CAmount amount)
{
    return GetL1Client().SendBMMRequest(hashBMM, hashBlockMain, nHeight, amount);
}

bool SidechainClient::GetCTIP(std::pair<uint256, uint32_t>& ctip)
{
    return GetL1Client().GetCTIP(ctip);
}

bool SidechainClient::RefreshBMM(const CAmount& amount, std::string& strError, uint256& hashCreatedMerkleRoot, uint256& hashConnected, uint256& hashConnectedMerkleRoot, uint256& txid, int& nTxn, CAmount& nFees, bool fCreateNew, const uint256& hashPrevBlock)
{
    //
    // A cache of recent mainchain block hashes and the mainchain tip is created
    // and updated.
    //
    // BMM blocks will be created if we haven't created one yet for the current
    // mainchain tip or if the mainchain tip has been updated since the last
    // time we created a BMM block. These BMM blocks do not have the critical
    // hash proof included yet as that requires a commit in a mainchain
    // coinbase.
    //
    // If a new BMM block is created then a BMM request will be sent via RPC to
    // the local mainchain node. This creates a transaction which pays miners to
    // include the critical hash required for our BMM block to be connected to
    // the sidechain.
    //
    // Then, the recent mainchain blocks including the tip will be scanned for
    // critical hash commitments for BMM blocks that we have created previously.
    //
    // If a critical hash commit is found in a mainchain block for one of the
    // BMM blocks we have created, a critical hash commit proof will be added
    // to our BMM block and then it will be submitted to the sidechain.
    //

    // Get list of the most recent mainchain blocks from the cache
    std::vector<uint256> vHashMainBlock = bmmCache.GetRecentMainBlockHashes();

    if (vHashMainBlock.empty()) {
        strError = "Failed to request new mainchain block hashes!";
        return false;
    }

    // Get our cached BMM blocks
    std::vector<CBlock> vBMMCache = bmmCache.GetBMMBlockCache();

    // If we don't have any existing BMM requests cached, create our first
    if (vBMMCache.empty() && fCreateNew) {
        CBlock block;
        if (CreateBMMBlock(block, strError, nFees, hashPrevBlock)) {
            nTxn = block.vtx.size();
            hashCreatedMerkleRoot = block.hashMerkleRoot;
            txid = SendBMMRequest(block.hashMerkleRoot, vHashMainBlock.back(), 0, amount);
            bmmCache.StorePrevBlockBMMCreated(vHashMainBlock.back());
            return true;
        } else {
            strError = "Failed to create new BMM block!";
            return false;
        }
    }

    // Check new main:blocks for our BMM requests
    for (const uint256& u : vHashMainBlock) {
        // Skip if we've already checked this block
        if (bmmCache.MainBlockChecked(u))
            continue;

        // Check main:block for any of our current BMM requests
        for (const CBlock& b : vBMMCache) {
            // Send 'verifybmm' rpc request to mainchain
            const uint256& hashMerkleRoot = b.hashMerkleRoot;
            uint256 txid;
            uint32_t nTime = 0;
            if (VerifyBMM(u, hashMerkleRoot, txid, nTime)) {
                CBlock block = b;

                // Copy the block time and hash from the mainchain block into
                // our new sidechain block.
                block.nTime = nTime;
                block.hashMainchainBlock = u;

                // Submit BMM block
                if (SubmitBMMBlock(block)) {
                    hashConnected = block.GetHash();
                    hashConnectedMerkleRoot = hashMerkleRoot;
                } else {
                    strError = "Failed to submit block with valid BMM!";
                    return false;
                }
            }
        }

        // Record that we checked this mainchain block
        bmmCache.AddCheckedMainBlock(u);
    }

    // Was there a new mainchain block since the last request we made?
    if (!bmmCache.HaveBMMRequestForPrevBlock(vHashMainBlock.back())) {
        // Clear out the bmm cache, the old requests are invalid now as they
        // were created for the old mainchain tip.
        bmmCache.ClearBMMBlocks();

        // Create a new BMM request
        if (fCreateNew) {
            CBlock block;
            if (CreateBMMBlock(block, strError, nFees, hashPrevBlock)) {
                // Send BMM request to mainchain
                nTxn = block.vtx.size();
                hashCreatedMerkleRoot = block.hashMerkleRoot;
                txid = SendBMMRequest(block.hashMerkleRoot, vHashMainBlock.back(), 0, amount);
                bmmCache.StorePrevBlockBMMCreated(vHashMainBlock.back());
            } else {
                strError = "Failed to create a new BMM request!";
                return false;
            }
        }
    } else {
        if (fCreateNew)
            strError = "Can't create new BMM request - already created for mainchain tip!";
    }

    return true;
}

bool SidechainClient::CreateBMMBlock(CBlock& block, std::string& strError, CAmount& nFees, const uint256& hashPrevBlock)
{
    if (!BlockAssembler(Params()).GenerateBMMBlock(block, strError, &nFees,
                std::vector<CMutableTransaction>(), hashPrevBlock)) {
        return false;
    }

    if (!bmmCache.StoreBMMBlock(block)) {
        // Failed to store BMM candidate block
        strError = "Failed to store BMM block!\n";
        return false;
    }

    return true;
}

bool SidechainClient::SubmitBMMBlock(const CBlock& block)
{
    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
    return ProcessNewBlock(Params(), shared_pblock, true, NULL);
}

bool SidechainClient::GetAverageFees(int nBlocks, int nStartHeight, CAmount& nAverageFee)
{
    return GetL1Client().GetAverageFees(nBlocks, nStartHeight, nAverageFee);
}

bool SidechainClient::GetBlockCount(int& nBlocks)
{
    return GetL1Client().GetBlockCount(nBlocks);
}

bool SidechainClient::GetWorkScore(const uint256& hash, int& nWorkScore)
{
    return GetL1Client().GetWorkScore(hash, nWorkScore);
}

bool SidechainClient::ListWithdrawalBundleStatus(std::vector<uint256>& vHashWithdrawalBundle)
{
    return GetL1Client().ListWithdrawalBundleStatus(vHashWithdrawalBundle);
}

bool SidechainClient::GetBlockHash(int nHeight, uint256& hashBlock)
{
    return GetL1Client().GetBlockHash(nHeight, hashBlock);
}

bool SidechainClient::GetAncestorHashes(const uint256& hashBlock, int nHeight, uint32_t nMax, std::vector<uint256>& vHash)
{
    return GetL1Client().GetAncestorHashes(hashBlock, nHeight, nMax, vHash);
}

bool SidechainClient::HaveSpentWithdrawalBundle(const uint256& hash)
{
    return GetL1Client().HaveSpentWithdrawalBundle(hash);
}

bool SidechainClient::HaveFailedWithdrawalBundle(const uint256& hash)
{
    return GetL1Client().HaveFailedWithdrawalBundle(hash);
}
