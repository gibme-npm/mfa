// Copyright (c) 2019-2023, Brandon Lehmann <brandonlehmann@gmail.com>
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
import HOTP, { HOTPConfig, HOTPConfigFinal } from './hotp';

export interface TOTPConfig extends HOTPConfig {
    /**
     * @default 60
     */
    period: number;
    /**
     * @default Date.now()
     */
    timestamp?: Date | number;
}

/** @ignore */
interface TOTPConfigFinal extends HOTPConfigFinal, TOTPConfig {}

export default abstract class TOTP extends HOTP {
    /**
     * Generates a TOTP token using the supplied configuration values
     *
     * @param config
     */
    public static generate (config: Partial<TOTPConfig> = {}): [string, Secret] {
        const _config = TOTP.mergeConfig(config);

        return super.generate(_config);
    }

    /**
     * Verifies a TOTP token using the supplied configuration values
     *
     * @param otp
     * @param config
     */
    public static verify (
        otp: string | number,
        config: Partial<TOTPConfig> = {}
    ): [boolean, number | null] {
        const _config = TOTP.mergeConfig(config);

        return super.verify(otp, _config);
    }

    /**
     * Returns a URI representation of the config
     *
     * @param config
     */
    public static toString (config: Partial<TOTPConfig> = {}): string {
        const _config = TOTP.mergeConfig(config);

        return super._toString(_config, 'totp', _config.period);
    }

    /**
     * Returns a QR code URL that will provide a scalable QR code of the config
     *
     * @param config
     * @param width
     * @param height
     */
    public static toQRCodeURL (
        config: Partial<TOTPConfig> = {},
        width = 256,
        height = 256
    ): string {
        return `https://chart.googleapis.com/chart?cht=qr&chs=${width}x${height}` +
            `&chl=${encodeURIComponent(TOTP.toString(config))}`;
    }

    /**
     * Merges the partial config with defaults
     *
     * @param config
     * @protected
     * @ignore
     */
    protected static mergeConfig (config: Partial<TOTPConfig>): TOTPConfigFinal {
        config.label ??= 'TOTP Authenticator';
        config.period ??= 60;
        config.timestamp ??= new Date();

        if (typeof config.timestamp === 'number') {
            config.timestamp = new Date(config.timestamp * 1000);
        }

        // stomp over any supplied counter settings because we are time based
        config.counter = Math.floor(config.timestamp.getTime() / 1000 / config.period);

        return super.mergeConfig(config) as any;
    }
}
