# ZETA STAGE TRACE CYPHER v0.2.2

A hardened PNG visual cipher that samples decimal windows from intermediate partial sums of ζ(2):

```text
ζ(2) = 1/1² + 1/2² + 1/3² + ...
```

This app does **not** read a stored, fixed ZETA digit table. The password-derived route selects calculation stages and arbitrary decimal positions, then local decimal windows are computed from the corresponding partial sums and folded into the keystream.

## v0.2 changes

- New carrier version: `v2`
- New inner payload magic: `ZST2`
- PBKDF2-SHA-256 iterations raised to 450,000
- Authentication tag expanded from 16 bytes to 32 bytes
- ZETA partial-sum sampling expanded to deeper stages and larger decimal positions
- Multiple stage windows are sampled per keystream block and folded through HMAC
- v0.1 PNG carrier decoding is preserved for compatibility

This is an experimental visual cipher, not a formally audited secure cryptosystem. It is intended for poetic, personal, visual, and experimental secrecy—not for high-value secrets.

## Deploy

```powershell
cd "$env:USERPROFILE\Desktop\zeta-stage-trace-cypher-v02"
npx wrangler pages deploy . --project-name zeta-stage-trace-cypher
```


## v0.2.2 update

- Increased the generated PNG layout width ceiling to support longer messages more gracefully.
- Large messages still produce larger PNGs and may take longer to generate/decode depending on the browser/device.
