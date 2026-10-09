# ⚠️ EVAL-ONLY FORK — NON-CONFORMANT

This fork of phoss-ap exists solely for a **disconnected internal evaluation** (Peppol
project PP1). It adds one config-gated switch that makes the AP-certificate trust anchor
overridable so the AP can run on a private test CA.

**It MUST NEVER be used against the real Peppol network.** A phoss-ap instance with
`eval.trusted-ca.path` set does not enforce Peppol PKI and is non-conformant. The accredited
production edge (PP3) uses **vanilla phoss-ap + real Peppol certificates**.

## Config

| Property | Meaning |
| --- | --- |
| `eval.trusted-ca.path` | Filesystem path to a PEM CA bundle. When set **and** `peppol.stage` is non-production, this CA replaces the official Peppol AP CA for both the startup check and the outbound receiver check (inbound inherits the startup checker). Unset or on production ⇒ stock behavior. |

**Required companion settings for the eval loopback** (our test CA issues no CRL/OCSP):
- `peppol.stage = test`
- `peppol.revocation.soft-fail = true`  ← otherwise revocation lookup fails the otherwise-trusted cert

Upstream: `phax/phoss-ap`. Rebase this branch (`eval-trust-override`) onto new upstream tags; the
change is confined to `EvalTrustAnchor` + two one-line call sites + one config key.
