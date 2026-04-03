# MFA/2FA One-Time Password (OTP) Library

A simple, lightweight library for generating and verifying one-time passwords supporting [TOTP](https://en.wikipedia.org/wiki/Time-based_one-time_password), [HOTP](https://en.wikipedia.org/wiki/HMAC-based_one-time_password), and [YubiKey OTP](https://www.yubico.com/products/).

## Documentation

[https://gibme-npm.github.io/mfa/](https://gibme-npm.github.io/mfa/)

## Installation

```bash
npm install @gibme/mfa
```

or

```bash
yarn add @gibme/mfa
```

### Requirements

- Node.js >= 22

## Usage

Import everything from the main entry point, or use subpath imports for tree-shaking:

```typescript
// Full import
import { Secret, TOTP, HOTP, YubiKeyOTP } from '@gibme/mfa';

// Subpath imports
import Secret from '@gibme/mfa/secret';
import TOTP from '@gibme/mfa/totp';
import HOTP from '@gibme/mfa/hotp';
import YubiKeyOTP from '@gibme/mfa/yubikey';
```

## Secret

The [seed](https://en.wikipedia.org/wiki/Random_seed) used with TOTP and HOTP one-time passwords. Generates a cryptographically random 20-byte secret by default.

### Generate

```typescript
import { Secret } from '@gibme/mfa';

const secret = new Secret();

console.log(secret.toString()); // base32-encoded string
```

### Restore from Existing Seed

```typescript
import { Secret } from '@gibme/mfa';

const secret = new Secret('ZK26SHUWGERAHUOTQMV7V3YMWIX4XUWS');
```

### Custom Size

```typescript
import { Secret } from '@gibme/mfa';

const secret = new Secret({ size: 32 });
```

## [TOTP](https://en.wikipedia.org/wiki/Time-based_one-time_password)

Time-based One-Time Password. The OTP is derived from the current time and a configurable period (default: 30 seconds). Compatible with authenticator apps such as Google Authenticator, Authy, and 1Password.

### Generate

```typescript
import { TOTP } from '@gibme/mfa';

const [token, secret] = TOTP.generate();

console.log(token);             // e.g. "482901"
console.log(secret.toString()); // base32 secret for storage
```

### Generate with Existing Secret

```typescript
import { TOTP, Secret } from '@gibme/mfa';

const secret = new Secret('ZK26SHUWGERAHUOTQMV7V3YMWIX4XUWS');
const [token] = TOTP.generate({ secret });
```

### Verify

```typescript
import { TOTP } from '@gibme/mfa';

const [success, delta] = TOTP.verify(token, { secret });

if (!success) {
    throw new Error('Invalid OTP code supplied');
}
```

### Generate OTPAuth URI

Generate a URI for provisioning authenticator apps:

```typescript
import { TOTP } from '@gibme/mfa';

const uri = TOTP.toString({
    secret,
    issuer: 'My App',
    label: 'user@example.com'
});
// otpauth://totp/user%40example.com?secret=...&issuer=My%20App&algorithm=SHA1&digits=6&period=30
```

### Generate QR Code URL

```typescript
import { TOTP } from '@gibme/mfa';

const qrUrl = TOTP.toQRCodeURL({
    secret,
    issuer: 'My App',
    label: 'user@example.com'
});
```

### Configuration Options

| Option | Type | Default | Description |
|---|---|---|---|
| `secret` | `Secret \| string` | Random | The shared secret |
| `period` | `number` | `30` | Time step in seconds |
| `digits` | `6 \| 8` | `6` | OTP digit count |
| `algorithm` | `DigestAlgorithm` | `SHA1` | Hash algorithm (`SHA1`, `SHA256`, `SHA512`) |
| `window` | `number` | `1` | Verification tolerance window |
| `issuer` | `string` | `''` | Issuer name for authenticator apps |
| `label` | `string` | `'TOTP Authenticator'` | Account label for authenticator apps |
| `timestamp` | `Date \| number` | `Date.now()` | Time reference for OTP calculation |

## [HOTP](https://en.wikipedia.org/wiki/HMAC-based_one-time_password)

HMAC-based One-Time Password. OTPs are generated based on a counter value that must be incremented after each use.

### Generate

```typescript
import { HOTP } from '@gibme/mfa';

const [token, secret] = HOTP.generate({ counter: 0 });
```

### Verify

```typescript
import { HOTP } from '@gibme/mfa';

const [success, delta] = HOTP.verify(token, { secret, counter: 0 });

if (!success) {
    throw new Error('Invalid OTP code supplied');
}
```

### Generate OTPAuth URI

```typescript
import { HOTP } from '@gibme/mfa';

const uri = HOTP.toString({
    secret,
    issuer: 'My App',
    label: 'user@example.com',
    counter: 0
});
```

### Generate QR Code URL

```typescript
import { HOTP } from '@gibme/mfa';

const qrUrl = HOTP.toQRCodeURL({
    secret,
    issuer: 'My App',
    label: 'user@example.com'
});
```

### Configuration Options

| Option | Type | Default | Description |
|---|---|---|---|
| `secret` | `Secret \| string` | Random | The shared secret |
| `counter` | `number` | `0` | HMAC counter value |
| `digits` | `6 \| 8` | `6` | OTP digit count |
| `algorithm` | `DigestAlgorithm` | `SHA1` | Hash algorithm (`SHA1`, `SHA256`, `SHA512`) |
| `window` | `number` | `1` | Verification tolerance window |
| `issuer` | `string` | `''` | Issuer name for authenticator apps |
| `label` | `string` | `'HOTP Authenticator'` | Account label for authenticator apps |

## [YubiKey](https://www.yubico.com/products/) OTP

Verify YubiKey one-time passwords against the Yubico validation servers.

To obtain a YubiKey API key, visit the [Yubico API key signup](https://upgrade.yubico.com/getapikey/) page.

### Verify

```typescript
import { YubiKeyOTP } from '@gibme/mfa';

const response = await YubiKeyOTP.verify(otp, {
    clientId: 12345,
    apiKey: 'yourapikey'
});

if (!response.valid) {
    throw new Error('Invalid OTP code supplied');
}

console.log(response.deviceId);       // YubiKey device identifier
console.log(response.signatureValid); // Server signature verification
console.log(response.status);         // Validation status code
```

### Configuration Options

| Option | Type | Default | Description |
|---|---|---|---|
| `clientId` | `number \| string` | Required | Yubico API client ID |
| `apiKey` | `string` | Required | Yubico API key |
| `serviceUrl` | `string` | `'https://api.yubico.com/wsapi/2.0/verify'` | Validation server URL |

### Validation Status Codes

| Status | Description |
|---|---|
| `OK` | OTP is valid |
| `BAD_OTP` | OTP is invalid format |
| `REPLAYED_OTP` | OTP has already been used |
| `BAD_SIGNATURE` | HMAC signature verification failed |
| `MISSING_PARAMETER` | Required parameter missing from request |
| `NO_SUCH_CLIENT` | Client ID does not exist |
| `OPERATION_NOT_ALLOWED` | Client ID not authorized for this operation |
| `BACKEND_ERROR` | Unexpected server error |
| `NOT_ENOUGH_ANSWERS` | Insufficient validation server responses |
| `REPLAYED_REQUEST` | Request with this nonce was already seen |

## License

MIT
