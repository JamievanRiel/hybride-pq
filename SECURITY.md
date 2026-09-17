# Security policy

## Status

hybride-pq has **not** been audited. Its primitives are standardized, but the PBP-1
combination has not been reviewed by independent cryptographers. Don't use it to
protect anything of real value. See the README section
"What it does NOT protect against" for the known limitations.

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Report them privately
through GitHub: open the **Security** tab of this repository and choose
**Report a vulnerability**.

Please include what you found, which component it affects (signatures, channel,
keystore, encodings), and, if possible, a way to reproduce it. You'll get a response as
soon as possible. Once a fix is available, the report will be published with credit to
you, unless you prefer otherwise.

## Scope

In scope: the PBP-1 design itself, the byte formats, parsing, and the channel and
keystore logic in this repository. Findings like "this combination is weaker than
claimed" are especially welcome.

Out of scope: bugs inside OpenSSL, `cryptography`, `pqcrypto` or `argon2-cffi`. Please
report those to the respective projects. It helps to also let us know when PBP-1 is
affected.
