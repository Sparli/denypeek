# Third-party notices

## gitleaks

keyhush's detection rules (`src/keyhush/rules.py`) are generated from the gitleaks default
configuration, `config/gitleaks.toml` at tag **v8.30.1**, fetched from
<https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/config/gitleaks.toml>.
An unmodified copy is kept at `tools/pinned/gitleaks.toml` (sha256
`e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`), and the generator is
`tools/gen_rules.py`.

The rules are changed as follows: Go-only regex syntax is rewritten for Python, rules that match
on file paths are left out, and literal example keys in allowlists are stored as SHA-256 hashes.
The upstream copy contains gitleaks' own public example keys in its allowlist.

Licence (from <https://github.com/gitleaks/gitleaks/blob/v8.30.1/LICENSE>):

```
MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
