// Package evidence implements the Trail Evidence Record v1 contract: a
// hash-chained, optionally signed JSON record that brokers, transfer workers,
// source bridges and ML pipelines can emit in one shared shape.
//
// The package covers three jobs:
//
//   - Seal computes content_hash and chain_hash for a record (RFC 8785 JCS,
//     SHA-256) and links it to the previous record of its stream.
//   - Sign attaches an Ed25519 signature over the chain_hash string.
//   - VerifyRecord and VerifyStream recompute everything from the bytes alone
//     and report findings in the error classes defined by SPEC.md.
//
// Canonicalisation is delegated to github.com/gowebpki/jcs, an RFC 8785
// implementation that includes the ES6 number formatting rules. The record
// shape and the verification algorithm are specified in SPEC.md at the
// repository root; this package follows that document, not the other way
// round.
package evidence
