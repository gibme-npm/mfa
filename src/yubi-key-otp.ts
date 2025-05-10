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

import fetch from '@gibme/fetch';
import { createHmac } from 'crypto';
import { v4 } from 'uuid';

export abstract class YubiKeyOTP {
    /**
     * Verifies a YubiKey OTP code
     *
     * @param config
     * @param otp
     * @param timeout
     */
    public static async verify (
        otp: string | number,
        config: YubiKeyOTP.Config,
        timeout = 5000
    ): Promise<YubiKeyOTP.ValidationResult> {
        if (typeof otp === 'number') {
            otp = otp.toString();
        }

        config.serviceUrl ??= 'https://api.yubico.com/wsapi/2.0/verify';

        const nonce = v4().replace(/-/g, '');

        const params: YubiKeyOTP.SigningParameters = {
            ...config.signingParameters,
            id: config.clientId,
            nonce,
            otp
        };

        const _params = YubiKeyOTP.construct_param_string(params);

        const signature = YubiKeyOTP.generate_signature(_params, config.apiKey);

        const url = `${config.serviceUrl}?${_params}&h=${signature}`;

        const result = await YubiKeyOTP.validate(url, timeout);

        const _checkParams = YubiKeyOTP.construct_param_string(result);

        const _signature = YubiKeyOTP.generate_signature(_checkParams, config.apiKey);

        result.t = new Date((result.t as any).split('Z')[0]);

        if (result.sl) {
            result.sl = parseInt(result.sl as any);
        }

        return {
            ...result,
            isOk: result.status === YubiKeyOTP.ValidationStatus.OK,
            deviceId: otp.substring(0, 12),
            signatureValid: _signature === result.h,
            valid: result.status === YubiKeyOTP.ValidationStatus.OK && _signature === result.h
        };
    }

    /**
     * Generates a message signature
     *
     * @param message
     * @param apiKey
     * @private
     */
    private static generate_signature (message: string, apiKey: string): string {
        const toOctet = (str: string): Int8Array => {
            const result: Int8Array = new Int8Array(str.length);

            for (let i = 0; i < str.length; i++) {
                result[i] = str.charCodeAt(i);
            }

            return result;
        };

        const _apiKey = Buffer.from(apiKey, 'base64');
        const _message = toOctet(message);

        return createHmac('sha1', _apiKey)
            .update(_message)
            .digest('base64');
    }

    /**
     * Constructs a message payload string
     *
     * @param params
     * @private
     */
    private static construct_param_string (params: any): string {
        return Object.keys(params)
            .filter(key => key !== 'h')
            .sort()
            .map(key => `${key}=${params[key]}`)
            .join('&');
    }

    /**
     * Validates a YubiKey OTP code with the YubiKey server(s)
     *
     * @param url
     * @param timeout
     * @private
     */
    private static async validate (
        url: string,
        timeout = 5000
    ): Promise<YubiKeyOTP.ValidationResponse> {
        const response = await fetch(url, {
            timeout
        });

        if (!response.ok) {
            throw new Error(`${response.url} [${response.status}]: ${response.statusText}`);
        }

        const data = await response.text();

        const result: any = {};

        data.split('\r\n')
            .filter(line => line.length !== 0)
            .forEach(line => {
                const index = line.indexOf('=');

                const key = line.substring(0, index).trim();

                result[key] = line.substring(index + 1).trim();
            });

        return result;
    }
}

export namespace YubiKeyOTP {
    export type SigningParameters = {
        timestamp?: string;
        sl?: string;
        timeout?: number;
        /**
         * The Yubico API client ID
         */
        id: string | number;
        /**
         * The OTP code
         */
        otp: string;
        /**
         * A nonce value to prevent replay attachs
         * @default <random>
         */
        nonce: string;

        [key: string]: any;
    }

    export type Config = {
        /**
         * The Yubico API client ID
         */
        clientId: number | string;
        /**
         * The Yubico API key
         */
        apiKey: string;
        /**
         * The Yubico OTP validation server url
         * @default https://api.yubico.com/wsapi/2.0/verify
         */
        serviceUrl?: string;
        signingParameters?: SigningParameters;
    }

    export enum ValidationStatus {
        OK = 'OK',
        BAD_OTP = 'BAD_OTP',
        REPLAYED_OTP = 'REPLAYED_OTP',
        BAD_SIGNATURE = 'BAD_SIGNATURE',
        MISSING_PARAMETER = 'MISSING_PARAMETER',
        NO_SUCH_CLIENT = 'NO_SUCH_CLIENT',
        OPERATION_NOT_ALLOWED = 'OPERATION_NOT_ALLOWED',
        BACKEND_ERROR = 'BACKEND_ERROR',
        NOT_ENOUGH_ANSWERS = 'NOT_ENOUGH_ANSWERS',
        REPLAYED_REQUEST = 'REPLAYED_REQUEST'
    }

    export type ValidationResponse = {
        /**
         * The validation signature
         */
        h: string;
        /**
         * The response timestamp
         */
        t: Date;
        /**
         * The OTP code
         */
        otp: string;
        /**
         * The server nonce to prevent replay attacks
         */
        nonce: string;
        sl?: number;
        /**
         * The status of the request
         */
        status: ValidationStatus;
    }

    export type ValidationResult = ValidationResponse & {
        /**
         * Whether the OTP presented is valid (okay)
         */
        isOk: boolean;
        /**
         * The YubiKey device ID that presented the OTP
         */
        deviceId: string;
        /**
         * Whether the response signature from the server is valid
         */
        signatureValid: boolean;
        /**
         * Set to `true` if both the OTP presented and the server response signature are valid
         */
        valid: boolean;
    }
}

export default YubiKeyOTP;
