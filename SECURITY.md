# Security policy

> **BEFORE THIS REPOSITORY IS MADE PUBLIC:** replace `SECURITY_CONTACT_ADDRESS`
> below with a real, monitored address, and delete this note. A disclosure
> policy that points nowhere is worse than none — it invites a researcher to
> find a hole, try to tell you, and give up.

## Reporting a vulnerability

Email **SECURITY_CONTACT_ADDRESS**. Please do not open a public issue for
anything with security impact.

Include what you need to make the problem reproducible: the construction or file
involved, what you expected, and what happens instead. A failing test against
the vectors in this repository is the most useful form a report can take.

You will get an acknowledgement that a human has read it. If a report turns out
to be a real issue, you will be told when a fix lands, and credited unless you
would rather not be.

## Scope

In scope — the cryptography in this repository:

- the constructions in `ios/MantelCrypto`, `android/crypto`, and `tools/vectors`
- disagreement between the three implementations
- anything that would let ciphertext be read, forged, or replayed without the
  corresponding key
- key derivation, key wrapping, and safety-number computation
- the test vectors themselves being wrong

Out of scope here — but still worth reporting to the same address:

- the hosted service and its infrastructure, which are not in this repository
- the client applications
- vulnerabilities in the underlying libraries (libsodium, swift-sodium,
  lazysodium) — report those upstream first; tell us too if Mantel's use of them
  makes the impact worse

## What this protocol is designed to resist

Stated plainly so a report can argue against it:

- **The server is not trusted with content.** Photos are encrypted on the device.
  The service stores ciphertext and cannot decrypt it.
- **Every key-wrapping operation authenticates the sender.** `crypto_box_seal` is
  not used anywhere, deliberately — anonymous sealing would let an attacker who
  can write to the key-distribution path insert keys that appear to come from a
  family member.
- **Password-derived keys use Argon2id** with parameters chosen to be expensive
  on commodity hardware.

What it does not claim to resist: a compromised device, a malicious build of the
client, or an attacker who has the user's password and recovery material. Those
are real limits, not omissions.

## Test vectors

`tools/vectors/vectors.json` is read-only by policy. Regenerating it is gated
behind an environment variable on purpose: a fixture that is regenerated to
match the implementation cannot catch the implementation drifting. If you
believe a vector is wrong, that is a finding — please report it rather than
regenerate.
