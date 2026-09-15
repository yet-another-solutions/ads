# Vendored rule set

`gitleaks.toml` is the default rule set from [gitleaks](https://github.com/gitleaks/gitleaks),
MIT licensed, copied unmodified.

It is vendored rather than invoked because gitleaks is a Go binary: shelling out once per
tool result would cost a process, and the valuable part is the rules, not the engine.
`ads_policy/secrets.py` reads this file and applies the same semantics — keyword prefilter,
regex, capture group, entropy floor, allowlists.

Updating means replacing this file and running the tests. Do not hand-edit it: local
additions belong in the policy document, so that they are versioned and reviewed like the
rest of the policy.

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
