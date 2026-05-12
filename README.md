# gosh.common

Shared Rust workspace for GOSH CLI and agent runtime/bootstrap protocol helpers.

Crates:

- `gosh-agent-runtime` (`gosh_agent_runtime`): join token schemas, runtime binding schemas, and exact binding registry.
- `gosh-agent-bootstrap` (`gosh_agent_bootstrap`): bootstrap bundle and X25519 keypair helpers.
- `gosh-credential-envelope` (`gosh_credential_envelope`): sealed-envelope decryption helpers and test vectors.

Downstream repositories should consume these crates from the private `gosh.common` git repository
with a pinned commit or tag. Local multi-repo checkouts can override that source with Cargo
`[patch."<git-url>"]` path entries; private CI should use Cargo's CLI git fetch mode with
HTTPS token credentials supplied by the CI environment. For the current GitHub organization that
source URL is `https://github.com/Futurizt/gosh.common.git`.
