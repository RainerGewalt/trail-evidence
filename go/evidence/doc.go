// Package evidence implements the Trail Evidence Record contract
// (trail.evidence/1, format 0.2): a hash-chained, optionally signed JSON
// record that brokers, transfer workers, source bridges and ML pipelines can
// emit in one shared shape, with the payload defined by a registered
// profile.
//
// The package covers four jobs:
//
//   - Seal computes content_hash and chain_hash for a record (RFC 8785 JCS,
//     SHA-256) and links it to the previous record of its stream. seq is
//     written as a decimal string.
//   - Sign attaches an Ed25519 signature over the chain_hash string.
//   - CheckRecord and VerifyStream recompute everything from the bytes alone,
//     give every record a state (valid, invalid, unknown, outside_scope) and
//     a profile state, and report findings in the classes defined by SPEC.md.
//   - Profiles, ProfileSchema and ValidateProfilePayload expose the profile
//     registry, which is embedded from profiles/ (a copy of the repository's
//     profiles/ directory, written by scripts/profiles.py).
//
// Canonicalisation is delegated to github.com/gowebpki/jcs, an RFC 8785
// implementation that includes the ES6 number formatting rules. The record
// shape and the verification algorithm are specified in SPEC.md at the
// repository root; this package follows that document, not the other way
// round.
package evidence
