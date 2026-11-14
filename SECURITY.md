# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/eric-minassian/auth/security/advisories/new)
rather than in a public issue. Include the affected component, a description of
the impact, and steps to reproduce.

## Scope

In scope: the protocol (`docs/protocol.md`), `crates/*`, `sdk/web`, `infra`,
and the formal models and proofs (a proof that does not establish what
`docs/verification.md` claims is a vulnerability).

The threat model and the residual risks that are accepted by design are listed
in [`docs/threat-model.md`](docs/threat-model.md).
