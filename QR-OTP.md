# QR/TOTP OP Authentication

`modules/otp-sec.cpp` adds a TOTP authenticator flow for Evangeline OP.

It does not decide channel privileges and does not send MODE directly. After a
valid TOTP code it calls:

```cpp
grantOpForAuthenticatedUser(from, NULL);
```

This keeps `qr-op <code>` behavior aligned with the normal `op <password>` path.

## Build

```sh
./configure --cc-options='-std=gnu++11 -fpermissive'
make dynamic
cd modules
make otp-sec
```

`libqrencode` is loaded dynamically at runtime. If it is unavailable, the module
still prints the manual key and `otpauth://` URI.

## Config

Load the module from the encrypted Evangeline config:

```text
load /path/to/modules/otp-sec.so
```

Runtime configuration is persisted in `qrcode-otp.txt` with `0600` permissions.

## Partyline

```text
.qrcode status
.qrcode enable
.qrcode disable
.qrcode set issuer Evangeline OTP
.qrcode set notification-type text
.qrcode set notification-type notice
.qrcode set setup-cooldown 60
.qrcode set qr-line-delay 2
.qrcode set qr-output compact
.qrcode set marco enable
.qrcode user marco show
.qrcode user marco disable
.qrcode user marco remove-secret
.qrcode user marco unlock
```

`disable` keeps the stored secret. `remove-secret` deletes it and disables QR OTP.
The authenticator label is built as `<issuer>:<handle>`, so with the default
issuer the app should show `Evangeline OTP` and the handle below it.

## User Flow

Setup:

```text
/msg BotNick qr-setup
```

The bot replies with:

```text
Manual key: <BASE32>
URI: otpauth://totp/...
<text QR code when libqrencode is available>
```

The user scans the QR code or enters the manual key, then replies with the
current 6-digit authenticator code. If valid, QR OTP is enabled and the bot
prints the `qr-op <6-digit code>` command to use next.

If QR OTP is already configured for that handle, `qr-setup` refuses the setup
and tells the user to contact an owner to remove the existing QR secret.

The text QR output is compact by default and rate-limited. Default is one QR
line every 2 seconds to avoid IRC `Excess Flood` disconnects.

Only one setup can be active for a handle at a time. Repeated setup requests are
rate-limited by `setup-cooldown`, and queued QR lines are capped to avoid flood
or memory abuse.

OP:

```text
/msg BotNick qr-op 123456
```

On success, Evangeline runs the same post-auth OP path used by `op <password>`.
Accepted TOTP counters are kept in memory per handle/host so the same code
cannot be replayed during the same validity window.
