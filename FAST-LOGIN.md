# FastLogin TOTP Partyline Authentication

`modules/fast-login.cpp` adds a TOTP authenticator login path for Evangeline
partyline/telnet access.

It lets an enabled partyline user log in with one line:

```text
<handle> <6-digit authenticator code>
```

This bypasses the normal `ownerpass`, `login`, and user password prompts only
after the handle has been explicitly enabled by a privileged owner and has
completed QR setup.

## Build

```sh
make dynamic
cd modules
make fast-login
```

`libqrencode` is loaded dynamically at runtime. If it is unavailable, setup
still prints the manual key and `otpauth://` URI.

After rebuilding `fast-login.so`, regenerate the encrypted config or reload the
module with the new MD5 signature. Otherwise Evangeline may refuse startup with:

```text
md5 signature missmatch
```

## Config

Load the module from the encrypted Evangeline config:

```text
load /path/to/modules/fast-login.so
```

Runtime configuration is persisted in `fast-login.txt` with `0600` permissions.

## Partyline Commands

Only owners with global `+s` or `+x` may manage FastLogin:

```text
.fastlogin status
.fastlogin enable
.fastlogin disable
.fastlogin <handle> show
.fastlogin <handle> enable
.fastlogin <handle> disable
.fastlogin <handle> remove-secret
.fastlogin <handle> unlock
```

`disable` keeps the stored secret. `remove-secret` deletes it and disables
FastLogin for that handle. Enabling a handle before setup creates:

```text
user <handle> allowed ON
user <handle> enabled OFF
```

After successful QR setup, it becomes:

```text
user <handle> allowed ON
user <handle> enabled ON
```

## User Setup

In private query to the bot:

```text
owner-setup
```

The bot matches the sender with `userlist.findHandleByHost()` and requires a
partyline handle with global `+p`. The bot then sends:

```text
Manual key: <BASE32>
URI: otpauth://totp/...
<text QR code when libqrencode is available>
```

The user scans the QR code or enters the manual key, then replies in the same
IRC query with the current 6-digit authenticator code.

## Telnet Login

Connect to the partyline port and send one line:

```text
marco 123456
```

On success, Evangeline marks the connection as a registered partyline connection
for that handle and shows the normal partyline logo.

## Failure Messages

FastLogin writes explicit telnet errors before closing:

```text
FastLogin failed: invalid or expired authenticator code.
FastLogin failed: this IP is temporarily locked.
FastLogin failed: code must be exactly 6 digits.
FastLogin failed: invalid handle or missing partyline +p flag.
FastLogin failed: handle is not enabled or setup is incomplete.
FastLogin failed: module is disabled or request is incomplete.
FastLogin failed: authenticator code was already used.
```

`owner-setup` also returns specific IRC errors for module disabled, hostmask
not matched, handle not enabled, existing secret, setup cooldown, and setup
lockout.

## Security Notes

- FastLogin is disabled by default.
- Management requires partyline owner privileges plus global `+s` or `+x`.
- Telnet login still requires a valid partyline handle with global `+p`.
- If `TELNET_OWNERS == 2`, the normal Evangeline IP/host restriction is enforced.
- Failed telnet FastLogin attempts are counted per source IP.
- After `max-attempts` failures, the source IP is locked for `lockout-time`
  seconds. Defaults are 3 attempts and 300 seconds.
- Accepted TOTP counters are cached per `handle|ip`, so the same code cannot be
  reused during the same validity window.
- Setup secrets are generated from `getrandom()` with `/dev/urandom` fallback.
- QR setup is bound to the IRC nick and full hostmask that requested it.

## Troubleshooting

If `owner-setup` says the module is disabled:

```text
.fastlogin enable
```

If `owner-setup` says the handle is not enabled:

```text
.fastlogin <handle> enable
```

If `owner-setup` says the IRC hostmask does not match, check:

```text
.whois <handle>
.+host <handle> *!ident@host
```

If telnet login closes after a rebuild with `md5 signature missmatch`, recreate
the encrypted config from the updated decrypted config:

```sh
cp conf.hub-email-otp.dec conf.hub-email-otp
./bin/evangeline -c conf.hub-email-otp
```
