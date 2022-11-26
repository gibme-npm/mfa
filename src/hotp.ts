// Copyright (c) 2019-2022, Brandon Lehmann <brandonlehmann@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import Secret from './secret';
import { createHmac, timingSafeEqual } from 'crypto';
import { Writer } from '@gibme/bytepack';

export enum DigestAlgorithm {
    SHA1 = 'sha1',
    SHA224 = 'sha224',
    SHA256 = 'sha256',
    SHA384 = 'sha384',
    SHA512 = 'sha512'
}

export interface HOTPConfig {
    /**
     * Displays as the "issuer" in most Authenticator applications
     * @default <empty>
     */
    issuer: string;
    /**
     * Displays as the account label in most Authenticator applications
     * @default 'Change Me'
     */
    label: string;
    /**
     * The algorithm to use for digest generation.
     *
     * Note: Most authenticator applications have limited support for anything other than SHA1
     *
     * @default SHA1
     */
    algorithm: DigestAlgorithm,
    /**
     * The number of digits to use for the OTP
     * @default 6
     */
    digits: 6 | 8;
    /**
     * The HOTP counter
     *
     * Note: This should be incremented upon each use to prevent replay attacks. user **must** also increment.
     *
     * Note: This value is overwritten when TOTP is used.
     * @default 0
     */
    counter: number;
    /**
     * The window of permitted OTP codes when verifying. A value of `1` would allow an OTP that is valid for the current
     * counter/period +/- 1. A value of `2` would allow +/- 2.
     * @default 1
     */
    window: number;
    /**
     * The Secret seed for the generation/validation of the OTP
     * @default <random>
     */
    secret: Secret | string;
}

/** @ignore */
export interface HOTPConfigFinal extends HOTPConfig {
    _secret: Secret;
}

export default abstract class HOTP {
    /**
     * Generates a HOTP token using the supplied configuration values
     *
     * @param config
     */
    public static generate (
        config: Partial<HOTPConfig> = {}
    ): [string, Secret] {
        const _config = HOTP.mergeConfig(config);

        const _counter = new Writer();

        _counter.uint64_t(_config.counter);

        const digest = HOTP.digest(_config.algorithm, _config._secret.buffer, _counter.buffer).valueOf();

        const offset = digest[digest.byteLength - 1] & 15;

        const otp =
            (((digest[offset] & 127) << 24) |
                ((digest[offset + 1] & 255) << 16) |
                ((digest[offset + 2] & 255) << 8) |
                (digest[offset + 3] & 255)) %
            10 ** _config.digits;

        return [otp.toString().padStart(_config.digits, '0'), _config._secret];
    }

    /**
     * Verifies a HOTP token using the supplied configuration values
     *
     * @param otp
     * @param config
     */
    public static verify (
        otp: string | number,
        config: Partial<HOTPConfig> = {}
    ): [boolean, number | null] {
        const _config = HOTP.mergeConfig(config);

        if (typeof otp === 'number') {
            otp = otp.toString().padStart(_config.digits, '0');
        }

        let delta = null;

        if (otp.length !== _config.digits) {
            return [false, delta];
        }

        for (let i = _config.counter - _config.window; i <= _config.counter + _config.window; ++i) {
            if (i < 0) {
                continue;
            }

            const [token] = HOTP.generate({
                ...config,
                counter: i
            });

            if (timingSafeEqual(Buffer.from(otp), Buffer.from(token))) {
                delta = i - _config.counter;
            }
        }

        return [delta !== null, delta];
    }

    /**
     * Returns a URI representation of the config
     *
     * @param config
     */
    public static toString (config: Partial<HOTPConfig> = {}): string {
        const _config = HOTP.mergeConfig(config);

        return HOTP._toString(_config, 'hotp') +
            `counter=${encodeURIComponent(_config.counter)}`;
    }

    /**
     * Returns a QR code URL that will provide a scalable QR code of the config
     *
     * @param config
     * @param width
     * @param height
     */
    public static toQRCodeURL (
        config: Partial<HOTPConfig> = {},
        width = 256,
        height = 256
    ): string {
        return `https://chart.googleapis.com/chart?cht=qr&chs=${width}x${height}` +
            `&chl=${encodeURIComponent(HOTP.toString(config))}`;
    }

    /**
     * Merges the partial config with defaults
     *
     * @param config
     * @protected
     * @ignore
     */
    protected static mergeConfig (config: Partial<HOTPConfig>): HOTPConfigFinal {
        config.issuer ||= '';
        config.label ||= 'HOTP Authenticator';
        config.algorithm ||= DigestAlgorithm.SHA1;
        config.digits ||= 6;
        config.counter ||= 0;
        config.window ||= 1;

        const _config: HOTPConfigFinal = config as any;

        if (config.secret instanceof Secret) {
            _config._secret = config.secret;
        } else {
            _config._secret = new Secret(config.secret);
        }

        return _config;
    }

    /**
     * Returns a URI representation of the config
     *
     * @param config
     * @param type
     * @protected
     */
    protected static _toString (
        config: HOTPConfig,
        type: 'totp' | 'hotp'
    ): string {
        const encode = encodeURIComponent;

        let url = `otpauth://${type}/`;

        url += config.issuer.length > 0
            ? `${encode(config.issuer)}:${encode(config.label)}?issuer=${encode(config.issuer)}`
            : `${encode(config.label)}?`;

        url += `secret=${encode(config.secret.toString())}&`;
        url += `algorithm=${encode(config.algorithm.toUpperCase())}&`;
        url += `digits=${encode(config.digits)}&`;

        return url;
    }

    /**
     * HMAC digest helper
     *
     * @param algorithm
     * @param key
     * @param payload
     * @private
     */
    private static digest (
        algorithm: DigestAlgorithm,
        key: Buffer,
        payload: Buffer
    ): Buffer {
        return createHmac(algorithm, key.valueOf())
            .update(payload.valueOf())
            .digest();
    }
}
