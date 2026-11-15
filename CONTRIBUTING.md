# Contributing

Thanks for your interest! HCRT is an experimental, single-file TLS 1.3 server.
Contributions, forks, issues and "wait, this actually works?" reports are all welcome.

## Run it locally

```sh
pip install cryptography h2 hpack hyperframe
cd examples && ./gen-certs.sh && cd ..
python3 hcrt.py examples/config.hcrt
# https://localhost:8443/
```

## Ground rules

- Keep `hcrt.py` a single self-contained file (that constraint is part of the charm).
- The TLS core is hand-rolled on purpose. Please don't swap it for `ssl` /
  `OpenSSL` — extending it (new cipher suites, RSA-PSS, more groups) is exactly
  the kind of PR we want.
- If you change the handshake, test against at least one real browser
  (Chrome or Safari) plus openssl, and say which you used in the PR.
- The demo sites under `sites/` are samples; keep them dependency-free static HTML.

## Good first issues

- RSA certificate support (RSA-PSS CertificateVerify)
- `TLS_AES_256_GCM_SHA384` / `TLS_CHACHA20_POLY1305_SHA256` suites
- `proxy` routes (reverse proxy instead of a static root)
- A browser-driven regression test for the ChronoCert rewind

## Reporting bugs

Please include: client (browser/openssl + version), the path sequence you
navigated, and the server log lines for your connection (they are printed with
your remote address). Never include real private keys.
