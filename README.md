# jwbmisc

Misc util functions.

## Passwords: `get_pass`

`get_pass` fetches a secret from one of several password managers. Each argument is a URL that says where the
secret lives in one password manager. The URLs are tried in order and the first one that succeeds wins:

```python
from jwbmisc import get_pass

token = get_pass(
    "keeper://AbC123xyz/password",  # 1st: Keeper, if installed
    "pass://work/github/token",     # 2nd: pass, if the binary exists
    "keyring://github/jwb",         # 3rd: OS keyring
    "env://GITHUB_TOKEN",           # last resort, e.g. in CI
)
```

This lets the same code run unchanged on machines with different password managers: the laptop gets the
secret from Keeper, a server with only `pass` uses the second URL, and CI falls through to the env var.

### Fallback rules

- **Manager not available:** the URL is skipped. `pass` needs the binary on `PATH`, `keyring` needs the
  module and a usable OS keyring, `keeper` needs `keepercommander`. `env://` and `file://` are always tried.
- **Secret not found or lookup failed:** `get_pass` moves on to the next URL.
- **All URLs failed:** a single `KeyError` lists every URL and why it failed.
- **Unknown scheme:** `ValueError` is raised right away, even if an earlier URL would have worked.
- **Ctrl-C** (e.g. during a Keeper login) aborts `get_pass`; it does not fall through.

### URL schemes

| Scheme | Example | Notes |
|---|---|---|
| `pass://` | `pass://work/db?lines=2,3&format=list` | `lines`: 1-based line numbers or `all` (default `1`); `format`: `raw` (default) or `list`. Binary can be changed with `JWBMISC_PASS_BIN`. |
| `env://` | `env://MY/NESTED/VAR` | `/` becomes `__`, so this reads `MY__NESTED__VAR`. |
| `file://` | `file:///run/secrets/token` | Content is stripped of surrounding whitespace. |
| `keyring://` | `keyring://service/username` | Requires the `keyring` package. |
| `keeper://` | `keeper://RECORD_UID/password` | Record UID, then an optional field type or label. Requires `keepercommander`; the session is stored in `~/.config/jwbmisc/keeper.json`. Login reads `KEEPER_USERNAME` and `KEEPER_SERVER` if set. |

### Interactive vs. non-interactive

`get_pass(..., interactive=True)` is the default and meant for CLI apps with a terminal: Keeper may ask for
SSO, 2FA or device approval, and gpg may show pinentry for `pass`.

With `interactive=False`, managers must not prompt and fall through instead:

- **Keeper** only uses a stored session; if a login would be needed, the URL is skipped.
- **pass** adds `--pinentry-mode error` to `PASSWORD_STORE_GPG_OPTS`, so gpg fails instead of prompting when
  the passphrase is not cached in gpg-agent. A cached passphrase still works.
- **keyring** is best effort: the OS (e.g. the macOS Keychain) may still show an access dialog.

```python
# e.g. in a cron job: never block on a prompt
token = get_pass("pass://work/github/token", "env://GITHUB_TOKEN", interactive=False)
```
