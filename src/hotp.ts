// Copyright (c) 2019-2025, Brandon Lehmann <brandonlehmann@gmail.com>
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

export abstract class HOTP {
    /**
     * Generates a HOTP token using the supplied configuration values
     *
     * @param config
     */
    public static generate (
        config: Partial<HOTP.Config<Secret | string>> = {}
    ): [string, Secret] {
        const _config = HOTP.mergeConfig(config);

        const _counter = new Writer()
            .uint64_t(_config.counter, true);

        const digest = HOTP.digest(_config.algorithm, _config.secret.buffer, _counter.buffer).valueOf();

        const offset = digest[digest.byteLength - 1] & 15;

        const otp =
            (((digest[offset] & 127) << 24) |
                ((digest[offset + 1] & 255) << 16) |
                ((digest[offset + 2] & 255) << 8) |
                (digest[offset + 3] & 255)) %
            10 ** _config.digits;

        return [otp.toString().padStart(_config.digits, '0'), _config.secret];
    }

    /**
     * Verifies a HOTP token using the supplied configuration values
     *
     * @param otp
     * @param config
     */
    public static verify (
        otp: string | number,
        config: Partial<HOTP.Config<Secret | string>> = {}
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
                break;
            }
        }

        return [delta !== null, delta];
    }

    /**
     * Returns a URI representation of the config
     *
     * @param config
     */
    public static toString (config: Partial<HOTP.Config<Secret | string>> = {}): string {
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
        config: Partial<HOTP.Config<Secret | string>> = {},
        width = 256,
        height = 256
    ): string {
        return `https://quickchart.io/chart?cht=qr&chs=${width}x${height}` +
            `&chl=${encodeURIComponent(HOTP.toString(config))}`;
    }

    /**
     * Merges the partial config with defaults
     *
     * @param config
     * @protected
     * @ignore
     */
    protected static mergeConfig<In extends HOTP.Config<Secret | string>, Out extends HOTP.Config<Secret>> (
        config: Partial<In>
    ): Out {
        config.issuer ??= '';
        config.label ??= 'HOTP Authenticator';
        config.algorithm ??= HOTP.DigestAlgorithm.SHA1;
        config.digits ??= 6;
        config.counter ??= 0;
        config.window ??= 1;
        config.secret ??= new Secret();

        if (!(config.secret instanceof Secret)) {
            config.secret = new Secret(config.secret);
        }

        return config as any as Out;
    }

    /**
     * Returns a URI representation of the config
     *
     * @param config
     * @param type
     * @param period
     * @protected
     */
    protected static _toString (
        config: HOTP.Config<Secret>,
        type: 'totp' | 'hotp',
        period?: number
    ): string {
        config.issuer = config.issuer.trim();
        config.label = config.label.trim();

        const encode = encodeURIComponent;

        let url = `otpauth://${type}/`;

        const prefix = (() => {
            const parts: string[] = [];

            if (config.issuer.length > 0) {
                parts.push(encode(config.issuer));
            }

            if (config.label.length > 0) {
                parts.push(encode(config.label));
            }

            return parts.join(':');
        })();

        url += `${prefix}?`;

        const suffix = new URLSearchParams();

        suffix.set('secret', config.secret.toString());
        suffix.set('algorithm', config.algorithm.toUpperCase());
        suffix.set('digits', config.digits.toString());

        if (period) {
            suffix.set('period', period.toString());
        }

        url += suffix.toString();

        if (config.issuer.length > 0) {
            url += `&issuer=${encode(config.issuer)}`;
        }

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
        algorithm: HOTP.DigestAlgorithm,
        key: Buffer,
        payload: Buffer
    ): Buffer {
        return createHmac(algorithm, key.valueOf())
            .update(payload.valueOf())
            .digest();
    }
}

export namespace HOTP {
    export enum DigestAlgorithm {
        SHA1 = 'sha1',
        SHA224 = 'sha224',
        SHA256 = 'sha256',
        SHA384 = 'sha384',
        SHA512 = 'sha512'
    }

    export type Config<SecretType extends Secret | string> = {
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
         * The window of permitted OTP codes when verifying. A value of `1` would allow an OTP that is valid for
         * the current counter/period +/- 1. A value of `2` would allow +/- 2.
         * @default 1
         */
        window: number;
        /**
         * The Secret seed for the generation/validation of the OTP
         * @default <random>
         */
        secret: SecretType;
    }
}

export default HOTP;
