# FreeBank

**Credit creation on a BIP 300/301 drivechain.** FreeBank is a Bitcoin sidechain for
free banking — *discount houses* issuing redeemable credit notes against attested
reserves, and *bills of exchange* backed by an escrow bond — in the lineage of Scottish
free banking (1716–1845), cryptographically translated. It runs as a CUSF/BIP 300–301
sidechain alongside the drivechain enforcer.

> Be your own bank. Make your own credit.

This is an exploration. It may or may not work out — but it illustrates just another
possibility that drivechains open up: not only new execution environments or scaling, but
new *monetary* arrangements settling against Bitcoin.

FreeBank is a C++ fork of the BitAssets sidechain chassis (MIT). It is **experimental,
pre-audit software** — run it on regtest/testnet/signet with test coins only.

## What works today

- **BIP 300/301 sidechain**: activates into a slot, advances by blind-merged-mining (BMM),
  credits deposits (M5), produces withdrawal bundles (M3) and completes the withdrawal
  payout (M6) — the full peg-out cycle.
- **CUSF enforcer transport**: FreeBank talks to the mainchain through the CUSF
  `bip300301_enforcer` gRPC surface, invoked at runtime via `grpcurl` (nothing of the
  enforcer is vendored or linked). BMM, deposit crediting and the **full withdrawal
  peg-out** are verified end-to-end on this path (revalidated against upstream
  `135115b`, July 2026); withdrawal bundles use the enforcer's `BlindedM6` wire layout.
- **Bills of exchange** (the credit primitive): a unique, stateful instrument with
  `bill_id = sha256(encrypted_body)` as its identity (the node never decrypts the body),
  a face amount, a maturity + grace window, a consensus-enforced escrow bond posted by the
  acceptor, and ownership advanced by endorsement. Full lifecycle — issue → endorse →
  retire/default with escrow claim — runs on-chain. RPCs: `issuebill`, `endorsebill`,
  `retirebill`, `claimbillescrow`, `listbills`, `getbill`, `listmybills`.
- **Discount houses** (the issuers): registered on-chain with a pledged escrow bond and
  M-of-N partner governance; lifecycle register → top-up / admit / exit → wind-down →
  reclaim, with time-locked exit tails and a one-governance-op-per-house-per-block rule.
  RPCs: `registerhouse`, `listhouses`, `attesthouse`, and friends.
- **Credit notes** (the money): per-house redeemable credit claims. Issuance is
  **reserve-gated at mint** — a mint must prove live reserves against the cap; notes
  transfer person-to-person; the issuing house redeems at par from reserves; a holder can
  place a formal *demand*, which accrues interest from the date of demand. RPCs:
  `mintnote`, `transfernote`, `redeemnote`, `demandnote`, `listmynotes`.
- **Reserve attestation and a lazy solvency machine**: houses attest their liquid till on
  a consensus cadence, proven coin-by-coin against the UTXO set. A missed cadence derives
  *Stressed*; an expired recovery window derives *Insolvent* — both computed at read time
  from on-chain heights (inherently reorg-safe). Insolvency triggers a waterfall:
  noteholders claim pro-rata from the locked escrow pot, then a whole-house residual
  settlement.
- **The option clause**, translated from the Scottish record: a stressed house may defer
  redemption for a bounded window, paying interest for the privilege, with its till locked
  into the claim pot; a consensus redemption spread (*brassage*) adds run-friction.
- **Term deposits**: time-locked deposits with a consensus interest floor and transferable
  receipts, subordinated to notes in the insolvency waterfall.
- **Clearing pools**: on-chain AMM pools between a house's notes and the base coin —
  swaps, LP shares, and orderly pool retirement. RPCs: `createpool`, `listpools`,
  `swapnote`, `addliquidity`, `removeliquidity`, `listmylp`, `retirepool`.
- **Metric denomination (display)**: RPCs report values in grams alongside base units at
  a fixed launch scale (`getgramrate`). Presentation-only — no consensus rule reads it.

## Wallet (preview)

A wallet GUI — desktop and browser (PWA) — is in development against a running
`freebankd`: notes, houses, clearing pools and bills, with balances led in grams.

![FreeBank wallet preview](doc/wallet-preview.png)

Wallet code: [mbdrivechains/freebank-gui](https://github.com/mbdrivechains/freebank-gui).

## Build

Native build (Ubuntu 24.04 shown; other platforms per standard Bitcoin Core build docs):

```sh
./autogen.sh
./configure --without-gui --with-incompatible-bdb --disable-bench
make -j"$(nproc)"
```

Binaries land in `src/`: `freebankd`, `freebank-cli`, `freebank-tx`.

Run the unit tests:

```sh
src/test/test_bitcoin
```

## Run

FreeBank is a sidechain — it needs a BIP 300/301 mainchain to merge-mine against. Point it
at the CUSF enforcer:

```sh
# gRPC via grpcurl; deposits and withdrawal-status also need the
# mainchain node's REST interface (bitcoind -rest -txindex)
freebankd -mainchaintransport=enforcer \
          -enforceraddr=127.0.0.1:50051 \
          -mainchainrest=127.0.0.1:8332
```

Advance the chain with `freebank-cli refreshbmm`, once the slot is active on the mainchain.

Full signet bring-up (topology, requirements, verification order): [`doc/signet.md`](doc/signet.md).

## License

MIT — see [`COPYING`](COPYING). Inherited from Bitcoin Core / the BitAssets chassis.

## Status

Alpha. Consensus surfaces (bills, houses, notes, attestation/insolvency, redemption
economics, term deposits, clearing pools, deposits/withdrawals, the transport layer) have
unit + integration coverage and adversarial review; the full peg-out cycle is verified
end-to-end against the CUSF enforcer (upstream ≥ `135115b`) on regtest. Reserve and
solvency parameters are provisional pending
simulation. Not yet audited; do not use with real value.
