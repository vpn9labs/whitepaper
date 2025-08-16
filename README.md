# VPN9: A Zero‑Logs, Open‑Source Consumer VPN

**Whitepaper v0.1**

---

## Abstract

VPN9 is a consumer‑focused, zero‑logs VPN with a fully open‑source stack. It is engineered for verifiable privacy, reproducible builds, and predictable performance under real‑world constraints. The system is composed of three public repositories:

* **`vpn9-portal`** — Ruby on Rails application for account lifecycle, privacy‑preserving payments, and public API.
* **`vpn9-service`** — Rust control plane and node/relay agents providing provisioning, key issuance, policy enforcement, and health orchestration.
* **`vpn9-app`** — Tauri‑based client for desktop and mobile implementing transport, kill‑switch, split tunneling, and local trust controls.

This document specifies the threat model, the cryptographic and network architecture, operational controls behind the zero‑logs claim, supply‑chain guarantees, interfaces between components, and the roadmap for post‑quantum agility and censorship resilience.

---

## 1. Design Principles

1. **Minimal data, maximally provable.** Collect nothing by default. Where telemetry is necessary, hold it in aggregate, in memory, and only long enough to manage capacity.
2. **Open by construction.** All code, build pipelines, IaC manifests, and security policies are public. No hidden components.
3. **Reproducibility over trust.** Users must be able to reproduce clients and verify binaries against source with deterministic outputs.
4. **Separation of concerns.** The portal never sees traffic metadata. The control plane never stores user PII. Exit nodes never learn account identity.
5. **Fail‑closed safety.** Any policy breach (interface down, daemon crash, handshake failure) forces a kill‑switch state.
6. **Threat‑model clarity.** VPN9 is a privacy tool for network confidentiality and location obfuscation. It is not an anonymity network against a truly global passive adversary.

---

## 2. Threat Model

### 2.1 Adversaries

* **Local and access‑network attackers.** Malicious Wi‑Fi, ISP observers, captive portals, and LAN peers performing sniffing, spoofing, or MITM.
* **On‑path regional observers.** IXPs, transit providers, and regional surveillance systems performing traffic correlation within limited scope.
* **Content‑side trackers.** DNS collectors, CDN edge correlation, and third‑party beacons measuring IP reputation and geolocation.
* **Malicious or compromised exit node.** Attempting packet inspection, DNS hijack, or metadata extraction.
* **Platform‑level interference.** OS APIs leaking traffic outside the tunnel; update supply‑chain tampering.
* **Targeted disruption.** UDP blocking, DPI against VPN handshakes, throttling, or connection resets.

### 2.2 Out of Scope

* **Global passive adversary** capable of full‑internet timing correlation.
* **Compromised endpoints.** Devices with resident malware or kernel‑level rootkits.
* **Application‑layer identity.** Logged‑in service accounts and browser fingerprints.

---

## 3. System Architecture

```
+-----------------+          +----------------------+           +--------------------+
|   vpn9-app      |  TLS1.3  |     vpn9-portal      |   gRPC    |    vpn9-service    |
| (Desktop/Mobile)|<-------->| (Rails, public API)  |<--------->| (Rust control plane)|
+--------+--------+          +----------+-----------+           +-----+--------------+
         |                                |                             |
         | WireGuard w/ obfuscation       |                             |
         v                                v                             v
   +-----+-------------------+     +------+----------------+     +------+----------------+
   |  Entry Relay (Agent)    |<--->| Regional Coordinator  |<--->| Exit Node (Agent)    |
   |  (vpn9-service/agent)   |     | (vpn9-service)        |     | (vpn9-service/agent) |
   +-------------------------+     +-----------------------+     +----------------------+
```

**Planes**

* **Control Plane (`vpn9-service`)**
  Rust microservices and agents:

  * **Coordinator:** device provisioning, policy distribution, path selection.
  * **CA/KMS:** short‑lived device certificates, node identity keys, HSM‑backed roots.
  * **Directory:** public list of regions, capabilities, and transparency attestations.
  * **Agent:** runs on relays/exits; receives signed policies; enforces datapath with nftables/eBPF; exposes minimal health endpoints.

* **Data Plane (Agents on Nodes)**
  WireGuard‑based tunnels with optional obfuscation layers. Entry and exit can be the same node (single‑hop) or different nodes (multi‑hop).

* **User Plane (`vpn9-app`)**
  Tauri shell with a Rust core. Integrates OS‑native VPN stacks (Wintun on Windows; NetworkExtension on macOS/iOS; VpnService/wireguard‑go on Android; kernel WireGuard on Linux when available). Implements kill‑switch, per‑app routing, and DNS policy.

* **Business Plane (`vpn9-portal`)**
  Runs account lifecycle, subscription credits, privacy‑preserving payment tokens, device limits, and support workflows. Publicly documented REST/GraphQL API.

---

## 4. Protocols and Cryptography

### 4.1 Transport

* **Primary:** WireGuard (NoiseIK) with Curve25519, ChaCha20‑Poly1305, BLAKE2s, and HKDF‑based key derivation.
* **Portability:** UDP default; UDP keepalives; NAT‑friendly timers.
* **Fallback/Obfuscation:**

  * **WG‑over‑QUIC** encapsulation to TCP/443 look‑alike where UDP is blocked.
  * **Pluggable fronting** providers via a simple trait in `vpn9-service` to add uTLS/TLS1.3 camouflage without changing client UX.

### 4.2 Control APIs

* **TLS 1.3 everywhere.** Ciphersuites: X25519 or P‑256 key exchange; AES‑GCM or ChaCha20‑Poly1305.
* **mTLS for nodes.** Node agents present short‑lived X.509 issued by VPN9 CA; clients pin CA via `vpn9-app` trust store.

### 4.3 Keys

* **Device keys:** Curve25519 static public key per device; stored only client‑side; registered to control plane via one‑time enrollment.
* **Session keys:** Ephemeral; rekeyed per WireGuard standard.
* **Node identity:** Long‑term Ed25519/25519 key pairs anchored in HSM; published in transparency ledger.
* **Payment tokens:** Chaumian blind signatures for unlinkable credit redemption (see §9).

---

## 5. Zero‑Logs Operating Model

**Definition.** “Zero logs” means: no retention of source IPs, connection timestamps, DNS queries, bandwidth usage per user, or application identifiers across any persistent medium. The system is engineered so these data are neither *produced* nor *storable* under default operation.

**Controls**

1. **Disk discipline:** Exit/relay nodes boot read‑only; journald set to `volatile`; swap disabled; `/var/log` on tmpfs with periodic shred at process exit.
2. **Flow tables:** NAT and conntrack counters exposed only as integers aggregated per node; never tagged with user or device identifiers.
3. **In‑memory health telemetry:** Node health (CPU, mem, packet drops, per‑region capacity) streamed via QUIC to control plane with lossy sampling; window ≤ 60 seconds; no IPs; no ports.
4. **DNS privacy:** On‑node Unbound/Bind in forwarding mode to VPN9 resolvers over DoT/DoH with ECS disabled. Optional blocklists run on exit; queries are never logged.
5. **Access controls:** Operators cannot enable per‑user logging without forking public code and leaving evidence in attestations.
6. **Legal posture:** No dynamic capability for “turning on logs”; no partially retained debug traces. Support diagnostics are generated client‑side with user opt‑in and scrubbed of IPs by design.

---

## 6. Client (`vpn9-app`) — Implementation and Guarantees

### 6.1 Architecture

* **Core:** Rust crate owning networking, platform FFI, policy parser, and attestation verifier.
* **Shell:** Tauri webview for UI; all privileged operations occur in Rust, not JS.
* **OS integrations:**

  * **Windows:** Wintun; kill‑switch via Windows Filtering Platform; firewall rules locked to WG interface.
  * **macOS/iOS:** NetworkExtension Packet Tunnel; kill‑switch via `NEOnDemandRuleDisconnect` + scoped routes.
  * **Linux:** Kernel WireGuard if present, otherwise wireguard‑go; kill‑switch via nftables sets bound to interface and peer pubkey.
  * **Android:** VpnService + wireguard‑go; disallow “always‑on” bypass.

### 6.2 Features

* **Kill‑switch:** Default on; traffic blocked when tunnel is down, DNS scoped to tunnel interface.
* **Split tunneling:** App‑based on Windows/macOS/Linux; domain‑based split via DoH policy; per‑route rules.
* **Multi‑hop:** Optional entry+exit selection with deterministic pathing; second hop never sees device account.
* **IPv6 first:** Full dual‑stack; NAT64/DNS64 support; ULA leak prevention.
* **Leak protection:** DNS leak tests, WebRTC local IP suppression toggle, local proxy exceptions disabled by default.
* **Autoupdate:** Code‑signed delta updates; user‑verifiable detached signatures.

### 6.3 Telemetry

* Off by default. Opt‑in sends crash minidumps with symbolicated stack traces *without* network state.

---

## 7. Control Plane and Node Agents (`vpn9-service`)

### 7.1 Coordinator Services

* **Enrollment:** Validates one‑time device code from portal; pins device pubkey; returns bootstrap: region directory + CA pinset.
* **Policy Engine:** Calculates best entry/exit for user constraints (region, latency, streaming rules) and network health.
* **Certificate Authority:** Issues short‑lived (e.g., 24h) device certificates for API use. Keys anchored in HSM; rotation automated.
* **Directory/Transparency:** Publishes signed snapshot of node fleet, software versions, build hashes, and attestation reports.

### 7.2 Node Agent

* **Datapath enforcement:** nftables/eBPF programs to bind WireGuard peer pubkeys to allowed routes; DNS forced to internal resolver; egress NAT consistent.
* **Process isolation:** Agent is the only process with WG private key; unprivileged sidecars for health checks; seccomp and ambient caps minimized.
* **Attestation:** On startup, agent submits: kernel hash, container image digest, commit ID, and build attestation (cosign/Sigstore). Control plane refuses drift.

### 7.3 Observability

* **What we see:** packet/handshake failure rates, queue drops, per‑node capacity slice, region‑level latency histograms.
* **What we never see:** source/destination IPs, per‑device throughput, or connection times.

---

## 8. Portal (`vpn9-portal`) — Accounts, Payments, API

### 8.1 Accounts

* **Identity:** Email‑based or passkey (WebAuthn). No usernames. 2FA optional (TOTP/WebAuthn).
* **Devices:** Soft‑limit per plan; device enrollment via short code; local device name exists only client‑side; server stores opaque device ID.

### 8.2 Privacy‑Preserving Payments

* **Credit model:** Portal mints time credits as blind‑signed tokens. User redeems tokens in control plane to enable service periods.
* **Unlinkability:** The token verifier (control plane) cannot link tokens to purchase events. The issuer (portal) cannot see which device redeems them.
* **Traditional payments:** If user pays by card/processor, the transaction lives with the processor; portal stores only the processor’s opaque subscription ID.
* **Alternative payments:** Support for privacy‑forward rails (e.g., cash‑equivalent vouchers or cryptocurrency) is implemented as separate token mints with identical redemption semantics.

### 8.3 Public API

* **Auth:** OAuth2 device flow; tokens bound to device certs; scopes limited to metadata (regions, versions).
* **Endpoints (illustrative):**

  * `POST /v1/device/enroll` – exchange enrollment code for bootstrap.
  * `GET /v1/regions` – signed directory snapshot with version/attestation hashes.
  * `POST /v1/token/redeem` – present blind token; receive service window receipt (no account identifiers).
  * `GET /v1/app/latest` – client update manifest and detached signatures.

---

## 9. Payment Token Flow (Blind Signatures)

**Goal:** Decouple payer identity from device service access.

**Protocol Outline**

1. Client obtains a **mint challenge** from portal and blinds a random token `T`.
2. Portal validates payment and signs blinded `T'` with mint private key; returns `S(T')`.
3. Client unblinds to obtain `S(T)`.
4. Client presents `T, S(T)` to control plane.
5. Control plane verifies `S(T)` against mint’s public key (published in transparency ledger), checks double‑spend set, grants service window, and stores only `H(T)` in a rolling Bloom filter.

**Properties**

* Issuer cannot link purchases to redemptions.
* Redeemer cannot trace tokens to accounts.
* Double‑spend prevention does not reveal redemption histories.

---

## 10. Reproducible Builds, Supply Chain, and Attestation

* **Deterministic builds:**

  * Clients: `vpn9-app` uses locked toolchains (`rust-toolchain.toml`), pinned NPM/Yarn/PNPM lockfiles, and deterministic Tauri bundles.
  * Services/Agents: `vpn9-service` containers built with pinned bases; `Cargo.lock` checked in; `--remap-path-prefix` ensures stable DWARF.
* **SBOMs:** CycloneDX generated for every artifact; shipped alongside releases.
* **Signing:** cosign/Sigstore with keyless (OIDC) and offline KMS‑backed keys; both published.
* **Attestations:** SLSA provenance for each build; node agents verify image digests before join; coordinator rejects nodes without matching attestations.
* **User verification:** CLI recipe to rebuild `vpn9-app` and verify checksums locally. Binaries refuse to run if detached signature missing or CA pinset mismatched.

---

## 11. DNS, Content Compatibility, and Optional Filtering

* **Resolvers:** In‑tunnel resolvers run with DNSSEC validation; ECS disabled.
* **Filtering (opt‑in):** Category blocklists applied on exit resolvers only; never at the portal or coordinator layers.
* **Streaming and geo:** Exit regions labelled with content compatibility hints; client pathing respects user‑selected region, never fakes geolocation beyond exit IP geography.

---

## 12. Censorship Resistance

* **Adaptive handshake:** Try UDP WireGuard; fall back to QUIC‑wrapped tunnel on TCP/443; optional pluggable transports behind a single “Stealth” toggle.
* **Traffic shaping:** Padding and MTU tuning to blend with HTTP/3 profiles when in stealth.
* **Decoy routing (future):** MASQUE‑style gateway support planned as an opt‑in path where lawful.

---

## 13. Performance Characteristics

* **Latency overhead:** Single‑hop within region expected to add single‑digit milliseconds; multi‑hop adds one additional regional RTT.
* **Throughput:** WireGuard saturates typical consumer links; QUIC‑wrapped mode trades \~5‑15% throughput for reachability.
* **Resource:** Client CPU remains bounded by crypto; mobile uses platform accelerators when available.

*(Numbers are directional targets; exact results depend on access network, device class, and distance to exit.)*

---

## 14. Security Program

* **Open development.** All issues and PRs public by default; security reports via private channel with 90‑day coordinated disclosure.
* **Third‑party audits.** Annual audits of client, control plane, and agents; reports published.
* **Bug bounty.** Tiered rewards for RCE, privacy bypass, and key/identity issues.
* **Continuous verification.** Canary releases, staged rollouts, crash monitoring sans network data.

---

## 15. Legal and Transparency

* **Transparency reports.** Semiannual report of legal requests, all denials due to absence of records, and any compliance actions.
* **Warrant canary.** Signed and updated on a fixed cadence.
* **Jurisdiction strategy.** Control plane and portal isolated from exit jurisdictions; exits placed with providers meeting minimum transparency and contract terms prohibiting logging requirements.

---

## 16. Roadmap (Forward‑Looking)

* **Post‑quantum agility.** Hybrid KEM for control plane TLS (X25519 + Kyber class), client‑verifiable negotiation, and gradual WG‑handshake PQC research.
* **MASQUE gateway.** HTTP/3‑native tunnels for high‑censorship regions.
* **Local DNS‑over‑Oblivious (ODoH/Oblivious DoH).** Resolver privacy beyond in‑tunnel DoH.
* **Accountless mode.** Pure token‑only devices with no portal identity.
* **Hardware attestation.** TPM/SEV‑SNP/Nitro proofs for nodes operating in public clouds, exposed in directory for user selection.

---

## 17. Interfaces and Schemas (Illustrative)

### 17.1 Enrollment (Client → Portal)

```
POST /v1/device/enroll
{ "enrollment_code": "ABCD-EFGH", "device_pubkey": "<base64>" }

200 OK
{
  "bootstrap": {
    "regions": [...],
    "coordinator": "https://api.vpn9.net",
    "ca_pinset": ["sha256/....", "sha256/..."],
    "attestations": [{"node_id": "...", "image": "sha256:..."}]
  },
  "device_token": "<JWT short-lived>"
}
```

### 17.2 Token Redemption (Client → Service)

```
POST /v1/token/redeem
{ "token": "<T>", "signature": "<S(T)>" }

200 OK
{ "service_until": "2025-12-01T00:00:00Z", "receipt": "sig..." }
```

### 17.3 Region Directory (Service → Client)

```
GET /v1/regions

200 OK
{
  "version": 42,
  "signed_at": "2025-08-01T00:00:00Z",
  "signature": "sig...",
  "regions": [
    {
      "id": "us-sea",
      "capabilities": ["wg", "quic-wrap", "multihop-exit"],
      "attestation": {"image": "sha256:...", "kernel": "sha256:..."}
    }
  ]
}
```

---

## 18. Operational Playbooks (Summary)

* **Incident: exit compromise suspected.** Immediately revoke node cert; remove from directory; publish revocation in transparency log; rotate fleet keys; publish post‑mortem.
* **CVE in dependency.** Automated advisories create PRs with pinned patches; rebuild; roll forward with canary wave; publish SBOM delta.
* **Jurisdictional pressure to log.** Exit is shut down; statement issued in transparency report; no logging capability exists in shipped agents.

---

## 19. Limitations and Honest Boundaries

* VPNs shift trust; they do not create anonymity against global observers.
* Application logins, browser fingerprinting, and side channels can still identify users.
* Some streaming or banking services may block known exit IPs; region rotation mitigates but cannot guarantee access.
* In stealth modes, throughput may be reduced to preserve reachability.

---

## 20. Repository Overview

### `vpn9-portal` (Rails)

* **Domains:** accounts, mint (blind‑signing service), billing adapters, email/passkey auth, device enrollment codes, public API.
* **Security:** CSRF hardened sessions, strict CSP, readonly DB roles for API, background jobs with idempotent mints, rate‑limits on enroll/redeem.
* **Data:** minimal PII (email, subscription state), processor IDs, mint public keys, transparency artifacts. No IP addresses retained.

### `vpn9-service` (Rust)

* **Crates:** `coordinator`, `ca`, `directory`, `agent`, `health`, `quicwrap` (optional), `attest`.
* **Runtime:** async Rust (Tokio), gRPC/HTTP, QUIC for inter‑node signals.
* **Agents:** systemd units with read‑only root; nftables/eBPF integration; sealed secrets for node certs.

### `vpn9-app` (Tauri + Rust)

* **Crates:** `client-core`, `platform-ffi`, `wireguard-if`, `policy`, `updater`, `verifier`.
* **UX:** minimal surface, region selection, multihop toggle, split tunneling per app/domain, stealth toggle.
* **Builds:** reproducible; detached signatures; platform‑native signing (Notarization on macOS, Authenticode on Windows, APK/AAB signing on Android, TestFlight/AltStore pipelines for iOS).

---

## 21. Compliance Mapping (Selective)

* **GDPR/CCPA:** Data minimization by construction; right to erasure trivial (delete email and payment linkage—service continues on redeemed tokens).
* **PCI scope:** Offloaded to payment processors; portal stores only opaque references.
* **SLSA:** Target level 3 for provenance; agents refuse non‑attested images.

---

## 22. Verification Checklist (For Users and Auditors)

1. Build `vpn9-app` from source; verify checksums of release binaries.
2. Inspect `vpn9-service` directory snapshot, attestation, and node image digests.
3. Confirm exit node logging paths are mounted `tmpfs`; verify `journald` volatile mode.
4. Confirm DNS resolvers disable ECS; verify with integrated DNS test.
5. Validate blind‑mint public key in portal versus service verifier key in directory.
6. Run integration tests that enforce kill‑switch behavior by forcibly terminating the tunnel interface and observing blocked egress.

---

## 23. Conclusion

VPN9 eliminates guesswork by making privacy verifiable. The architecture isolates concerns, minimizes data, and exposes the full system—including builds and policies—to public scrutiny. The product is consumer‑grade in usability and uncompromising in security posture. The roadmap keeps the stack agile against censorship and cryptographic shifts.

---

## Appendix A — Kill‑Switch Rules (Illustrative)

**Linux (nftables)**

```
table inet vpn9 {
  set wg_peers { type ipv4_addr; flags interval; }
  chain output {
    type filter hook output priority 0;
    ip daddr @wg_peers accept
    ip daddr {10.64.0.0/10} accept
    meta oifname "wg0" accept
    ct state established,related accept
    counter drop
  }
}
```

**Windows (WFP)**
Block all outbound except to WireGuard peer and local loopback when `wg0` down; rules bound to interface GUID.

---

## Appendix B — Data We Keep (and For How Long)

* Email (if provided), subscription state, payment processor opaque ID. **Retention:** while subscription active + tax/legal minimum.
* Blind‑token spent set `H(T)`. **Retention:** rolling window ≤ service period + grace (e.g., 7 days).
* Aggregate node health metrics (no IPs). **Retention:** sliding window ≤ 24h.
* Crash reports (opt‑in). **Retention:** 30 days; scrubbed.

**We do not collect or retain:** source IP, connection timestamps, DNS queries, ports, per‑device throughput.

---

## Appendix C — Build Reproduction (Sketch)

1. `git clone` all three repos at tagged release.
2. Install pinned toolchains via `rustup` and `asdf` (Ruby/Node).
3. `make sbom && make build && make attest`.
4. Verify cosign signatures and SLSA provenance.
5. On Linux, confirm `sha256sum` of `vpn9-app` matches published detached signature.

---

## Appendix D — Glossary

* **Attestation:** Cryptographic evidence of how/where software was built.
* **Blind signature:** Signature on a hidden message enabling unlinkable redemption.
* **ECS:** EDNS Client Subnet.
* **MASQUE:** HTTP/3 mechanism for proxying UDP/QUIC.
* **SLSA:** Supply‑chain Levels for Software Artifacts.

---

**Status:** Draft for public review. Contributions are expected. Audits are mandatory before “stable” designation of any major feature.
