# Email OTP module

`modules/otp-sec.cpp` adds a private-message email OTP flow for the normal Evangeline OP command.

The module does not decide channel privileges. After a valid OTP it calls the shared core helper:

```cpp
grantOpForAuthenticatedUser(from, NULL);
```

That helper uses the same channel scan and `modeQ[PRIO_LOW].add("+o")` behavior as the historical `op <password>` command. The mode queue still revalidates channel state and `HAS_O` before sending `MODE +o`.

## Build

Build the bot and module:

```sh
./configure --cc-options='-std=gnu++11 -fpermissive'
make dynamic
cd modules
make otp-sec
```

The Evangeline tree contains SASL/SCRAM code that needs C++11, while the legacy core still needs `-fpermissive` with modern compilers. The module uses OpenSSL for SHA-256, pthread for the SMTP worker, and libcurl at runtime through `dlopen("libcurl.so.4")`. This avoids a build-time dependency on `curl/curl.h`, but `libcurl.so.4` must be installed on the host.

## Load

Add the unified OTP module to the normal Evangeline module load configuration, using the local module path/name used by this installation, for example:

```text
load /path/to/modules/otp-sec.so
```

## Partyline commands

Global:

```text
.email-otp status
.email-otp enable
.email-otp disable
.email-otp smtp
.email-otp help
```

Settings:

```text
.email-otp set smtp-host smtp.example.com
.email-otp set smtp-port 587
.email-otp set smtp-security starttls
.email-otp set smtp-user bot@example.com
.email-otp set smtp-password secret
.email-otp set smtp-from bot@example.com
.email-otp set smtp-from-name Evangeline
.email-otp set verify-tls on
.email-otp set otp-length 6
.email-otp set otp-ttl 300
.email-otp set max-attempts 3
.email-otp set lockout-time 18000
.email-otp set resend-cooldown 60
.email-otp set hourly-limit 5
.email-otp set notification-type text
.email-otp set notification-type notice
```

Users:

```text
.email-otp user Marco show
.email-otp user Marco set-email marco@example.com
.email-otp user Marco enable
.email-otp user Marco disable
.email-otp user Marco remove-email
.email-otp user Marco unlock
```

Setting a new email leaves the user disabled. `disable` keeps the email. `remove-email` clears the email, disables the user, and invalidates runtime sessions.

## Example config

The module persists `email-otp.txt` with `0600` permissions when possible:

```text
set module-enabled ON
set smtp-host smtp.example.com
set smtp-port 587
set smtp-security starttls
set smtp-user bot@example.com
set smtp-password secret
set smtp-from bot@example.com
set smtp-from-name Evangeline
set verify-tls ON
set otp-length 6
set otp-ttl 300
set max-attempts 3
set lockout-time 18000
set resend-cooldown 60
set hourly-limit 5
set notification-type text
user Marco email marco@example.com
user Marco enabled ON
```

Runtime OTP sessions, OTP hashes, pending delivery state, rate limits, and lockouts are not saved.

## User flow

In private query to the bot:

```text
email-otp
```

After successful email delivery:

```text
Verification code sent. Check your email and reply here with: op-email <6-digit code>.
```

Then:

```text
op-email 123456
```

On success:

```text
Verification successful.
```

## Security notes

- User identity is matched from the full `nick!ident@host` mask with `userlist.findHandleByHost()`.
- Unknown user, missing email, or disabled user receives the same generic unavailable message.
- OTP values are generated from `getrandom()` with `/dev/urandom` fallback.
- OTP values are hashed as `SHA-256(nonce || otp)` in memory.
- OTP values and SMTP passwords are not logged.
- SMTP is sent by a worker thread; the thread does not call Evangeline IRC, userlist, or mode queue APIs.
- A valid OTP is single-use.
- A new request invalidates any existing session for the same handle.
- Lockout key is `HANDLE + ident@host`, so it survives nick changes for the same host identity.

## Test plan

Identity:

```text
unknown hostmask -> generic unavailable message and no SMTP job
host not matching handle -> generic unavailable message and no SMTP job
valid user with enabled email -> SMTP job and session after delivery
valid user disabled -> generic unavailable message
valid user without email -> generic unavailable message
```

OTP:

```text
correct OTP -> Verification successful and shared OP helper called
wrong OTP -> attempts decrement
three wrong OTPs -> lockout
expired OTP -> expired message and session removal
replay after success -> no session, no OP
old OTP after resend -> fails because previous session is invalidated
letters, too short, too long -> invalid verification code while session exists
```

Rate limiting:

```text
two immediate email-otp requests -> second rejected
more than hourly-limit requests in one hour -> rejected
request during lockout -> rejected, no SMTP
```

Identity changes:

```text
nick change before OTP submit -> session rejected
host change before OTP submit -> session rejected
handle removed before OTP submit -> no success
flags removed before OTP submit -> shared OP helper/mode queue does not grant +o
```

OP equivalence:

```text
op password
email-otp, then op-email with valid OTP
```

For the same `nick!ident@host`, both paths must enqueue `+o` on the same channels. A user with `HAS_O` only on `#one` and present on `#one`, `#two`, `#three` should only receive `+o` on `#one`; a user with global OP privileges should match the historical `op password` result.

Sanitizers:

```sh
CXXFLAGS="-fsanitize=address,undefined -g" make dynamic
cd modules
g++ -fPIC -fsanitize=address,undefined -g -o otp-sec.so otp-sec.cpp -shared -lssl -lcrypto -lpthread -ldl
```

Run the bot in a test network and exercise the flows above while checking for leaks, invalid memory access, undefined behavior, and obvious thread issues.
