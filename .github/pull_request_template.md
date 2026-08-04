<!-- Security impact? Do not open a PR. See SECURITY.md. -->

**What does this change, and why?**

**Checklist**

- [ ] All three test suites pass locally (Swift, Kotlin with `--rerun-tasks`, JS)
- [ ] If one implementation changed, the others were checked for the same issue
- [ ] No novel cryptography — every primitive is a standard libsodium construction
- [ ] `tools/vectors/vectors.json` is unchanged **or** the change is a deliberate
      protocol change, explained below
- [ ] New tests were mutation-tested: broken on purpose, confirmed red, restored

**If a vector changed, why?**
<!-- Regenerating the fixture to make a failing test pass is not a reason. -->
