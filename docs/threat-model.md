# Threat model

Who CANARY TRAP is defending against, what it defends, and — more usefully —
where it does not defend. Written against the code as it actually is, not as it
is described elsewhere.

## 1. Assets

| Asset | Where it lives | If lost |
|---|---|---|
| Document content | only inside `.ct` containers, encrypted per-variant | confidentiality breach |
| Variant keys | Shamir shares in `chronicle` (`key_shares` table) | the whole attribution guarantee |
| Recipient private keys | `data/client_keys/*.bin`, never transmitted | forgery of decrypt requests |
| Watermark master seed | `CANARY_TRAP_*_SEED_2026` defaults, overridable by env | every copy becomes unattributable |
| Ledger | `canarytrap_ledger.db` per node | evidence trail |
| Evidence bundles | produced on demand | admissibility |

## 2. Adversaries

**A1 — Curious recipient.** Has legitimate keys and a decrypted copy. Wants to
leak it anonymously.
*Defence:* every copy is uniquely watermarked, and the watermark is bound to a
signed, committed session. Leak ⇒ named recipient.
*Weakness:* the watermark is typographic. Re-typesetting, re-printing, or
screenshot-then-retypes loses it. Photographed screens are not covered at all.

**A2 — Rogue recipient with a modified client.** Skips the validator entirely and
tries to decrypt offline.
*Defence:* variant keys only exist as `t=3` Shamir shares; the container carries
both variants' ciphertext but no keys. Without a committed request the shares
are never released, and the ciphertext is useless. Demonstrated by
`gauntlet/attacks/bypass_client.py`.

**A3 — Hostile node administrator.** Full filesystem access to one validator's
SQLite file. Tries to rewrite history or frame an innocent.
*Defence:* entry hashes, Merkle roots and `prev_hash` links are recomputed on
every integrity scan; altering a row breaks the chain. Demonstrated by
`gauntlet/attacks/tamper_database.py`.
*Weakness:* an administrator who controls **three of four** nodes can rewrite the
chain consistently and re-sign it, because quorum enforcement is incomplete
(§4.1).

**A4 — Colluding recipients.** Compare copies, splice them to blur attribution.
*Defence:* the codeword is per-session, so a 50/50 splice yields ~50% match for
both colluders against a ~50% innocent baseline, and both are surfaced.
Demonstrated by `gauntlet/attacks/collude_splicing.py`.

**A5 — Network attacker / outside observer.** Sees traffic or hosts.
*Defence:* the system is air-gapped by design. Post-quantum primitives limit the
value of "harvest now, decrypt later".

**A6 — Malicious recipient host owner.** Has the machine the daemon runs on.
*Weakness:* this is the hard one. A compromised host can read the assembled PDF
from memory, screen-capture it, or instrument the daemon. The design bounds the
*blast radius* — one copy is attributable, others are not — but it cannot
prevent capture. It also cannot stop a host from lying about *which* copy it
produced.

## 3. Out of scope

- Physical attacks on the recipient's hardware.
- Traffic analysis and endpoint compromise.
- Anything requiring a network or a cloud service; the system is designed to run
  with none.
- Attribution of a document that was retyped from scratch rather than copied.

## 4. Current weaknesses, ranked

1. **Quorum is not enforced (critical).** `warden/consensus.py` collects peer
   votes but commits even when fewer than three signatures are present — the
   missing-quorum branch is a no-op. One reachable node can therefore commit
   alone. The `≥3-of-4` claim is not currently true of the code. This is the
   single most important fix; it is item 1 in `docs/roadmap.md`.
2. **Manifest signatures are not verified (high).** `warden/service.py` stores
   the sender's signature on a `MANIFEST` entry but never checks it, so anyone
   who can reach the endpoint can register a manifest naming arbitrary
   recipients for a document hash.
3. **Quorum certificates are not uniformly defined (high).** The proposer signs
   a candidate header, the offline verifier checks signatures against the block
   hash, and a signature with no accompanying public key is counted as valid.
   Evidence bundles therefore prove recipient non-repudiation strongly and the
   quorum layer weakly.
4. **Shamir shares are stored in cleartext (medium).** The column is named
   `encrypted_share` but holds base64-decoded share bytes. Anyone with read
   access to the node's database can combine shares from different documents and
   reconstruct variant keys.
5. **Extraction strategy 1 is ground truth (medium).** It regex-reads `Tw`
   operators out of the content stream and reports full confidence, so it only
   works on files that still carry the operators. The geometric strategy is the
   one that survives re-rendering, and it is the weaker of the two.
6. **No error correction (medium).** A single mis-recovered bit costs a full
   block. Reed-Solomon over the codeword is the planned mitigation.
7. **Throwaway recipient keys (low).** `ct/sender.py` generates a temporary
   ML-KEM key when a recipient's public key file is missing, so the demo
   continues but that recipient can never decrypt.
8. **Authorisation is by identity list only.** There is no revocation effect on
   already-issued containers; `is_revoked` is checked on new requests only.

## 5. Assumptions

- The four validator nodes are operated by independent administrative domains.
- Node clocks are roughly synchronised; the block timestamp is the median of
  collected peer clocks.
- The watermark master seed is kept secret from recipients.
- The recipient's private keys stay on the recipient's device.
- Nothing in the pipeline reaches the network at runtime.
