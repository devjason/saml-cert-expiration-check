# saml-cert-expiration-check
Loads certificate information from a SAML metadata URL or encoded string and returns expiration date

usage: check.py [-h] {cmdline,url} data

## Examples
1. Load from SAML metadata URL
```
python check.py url "https://example.com/saml/metadata"
```

2. Paste X.509 cert
```
python check.py cmdline "MIIGbzCCBVegAwIBAgIRAJphmAXC6GR8omPixrWd8QowDQYJKoZIhvcNAQELBQAwgY8xCzAJBgNV....=="
```

