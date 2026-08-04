# Contributing

Thanks for looking at this. The most valuable contribution to this repository is
usually not a patch — it is a demonstration that something here is wrong.

## Found a security problem?

**Do not open an issue.** See [SECURITY.md](SECURITY.md).

## Reporting a cryptographic disagreement

If one implementation disagrees with another, or with
[`tools/vectors/vectors.json`](tools/vectors/vectors.json), that is a finding
whether or not you can explain it. A failing test is a complete report.

## The rule that shapes everything here

**The implementations must match the vectors. The vectors do not get regenerated
to match the implementations.**

`tools/vectors/vectors.json` is read-only by policy, and regenerating it is gated
behind an environment variable deliberately. A fixture that is regenerated
whenever a test fails cannot catch an implementation drifting — it just records
whatever the code currently does. If your change makes a vector test fail, the
default assumption is that your change is wrong.

Changing a vector is legitimate when the protocol itself is intended to change.
That is a deliberate act, reviewed as such, and CI will flag it on the pull
request so it cannot pass unnoticed.

## Cryptographic changes

- **No novel cryptography.** Every primitive here is a standard libsodium
  construction. Patches introducing a hand-rolled cipher, mode, KDF, or padding
  scheme will be declined regardless of quality.
- **`crypto_box_seal` is not used, on purpose.** Anonymous sealing hides the
  sender, and every place this protocol wraps a key for another member is a place
  where the sender must be authenticated. Patches adding it need to argue that
  case first.
- **Variant keys come from `deriveVariantKey`.** Deriving them another way, even
  equivalently, breaks the property that one collection key yields exactly one
  set of variant keys.
- A change to one implementation almost always needs the same change to the other
  two. That is the point of having three.

## Running the tests

```bash
cd ios/MantelCrypto && swift test          # Swift
./gradlew :crypto:test --rerun-tasks       # Kotlin (JVM, no emulator)
cd tools/vectors && npm ci && npm test     # JavaScript oracle
```

`--rerun-tasks` is not decoration: an `UP-TO-DATE` Gradle task prints no failures
and reads exactly like a pass.

## Tests

A test that cannot fail is worse than no test, because it reports success.
Before submitting, break your own change deliberately and confirm the test goes
red — then put it back. If a case cannot be made to fail by any single-line
mutation, say so in the pull request rather than leaving it in for appearance.

## Style

Match the surrounding code. Comments here explain *why*, especially where a
choice looks arbitrary but is load-bearing — several constants in this repository
are wire format and cannot be changed without breaking every existing file.
