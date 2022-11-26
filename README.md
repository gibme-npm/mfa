# MFA/2FA One-Time Password (OTP) Library

## Documentation

[https://gibme-npm.github.io/mfa/](https://gibme-npm.github.io/mfa/)

## Secret

The [seed](https://en.wikipedia.org/wiki/Random_seed) used with TOTP and HOTP one-time password(s).

### Generate

```typescript
import { Secret } from '@gibme/mfa';

const secret = new Secret();

console.log(secret.toString());
```

### Restore

```typescript
import { Secret } from '@gibme/mfa';

const secret = new Secret('ZK26SHUWGERAHUOTQMV7V3YMWIX4XUWS');
```

## [TOTP](https://en.wikipedia.org/wiki/Time-based_one-time_password)

Used to create and/or verify a Time-based one-time password. The OTP value is based upon the current time and the period specified.

### Generate

```typescript
import { TOTP } from '@gibme/mfa';

const [token] = TOTP.generate({ secret });
```

### Verify

```typescript
import { TOTP } from '@gibme/mfa';

const [success, delta_window] = TOTP.verify(token, { secret });

if (!success) {
    throw new Error('Invalid OTP code supplied');
}
```

## [HOTP](https://en.wikipedia.org/wiki/HMAC-based_one-time_password)

Used to create and/or verify a HMAC-based one-time password. OTPs are generated based upon the counter value supplied.

### Generate

```typescript
import { HOTP } from '@gibme/mfa';

const [token] = HOTP.generate({ secret, counter: 2 });
```

### Verify

```typescript
import { HOTP } from '@gibme/mfa';

const [success, delta_window] = HOTP.verify(token, { secret, counter: 2 });

if (!success) {
    throw new Error('Invalid OTP code supplied');
}
```

## [YubiKey](https://www.yubico.com/products/) OTP

To obtain a YubiKey API key head on over to the [Yubico API key signup](https://upgrade.yubico.com/getapikey/) page.

### Verify

```typescript
import { YubiKeyOTP } from '@gibme/mfa';

(async () => {
    const response = await YubiKeyOTP.verify(token, {
        clientId: 12345,
        apiKey: 'yourapikey'
    })
    
    if (!response.valid) {
        throw new Error('Invalid OTP code supplied');
    }
})();
```
