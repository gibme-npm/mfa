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

import assert from 'assert';
import { it, describe } from 'mocha';
import { Secret, TOTP, HOTP, YubiKeyOTP } from '../src/mfa';
import * as dotenv from 'dotenv';

dotenv.config();

const sleep = async (timeout: number) => new Promise(resolve => setTimeout(resolve, timeout));

describe('TOTP Tests', () => {
    const secret = new Secret();

    it('Generate', () => {
        const [, _secret] = TOTP.generate({ secret });

        assert(secret.toString() === _secret.toString());
    });

    it('Verify', () => {
        const [token] = TOTP.generate({ secret });

        const [success] = TOTP.verify(token, { secret });

        assert(success);
    });

    it('Verify [Failure]', async () => {
        const [token] = TOTP.generate({ secret, period: 2 });

        await sleep(5_000);

        const [success] = TOTP.verify(token, { secret, period: 2 });

        assert(!success);
    });
});

describe('HOTP Tests', () => {
    const secret = new Secret();

    it('Generate', () => {
        const [, _secret] = HOTP.generate({ secret });

        assert(secret.toString() === _secret.toString());
    });

    it('Verify', () => {
        const [token] = HOTP.generate({ secret });

        const [success] = HOTP.verify(token, { secret });

        assert(success);
    });

    it('Verify [Failure]', async () => {
        const [token] = HOTP.generate({ secret });

        const [success] = HOTP.verify(token, { secret, counter: 2 });

        assert(!success);
    });
});

describe('YubiKey Tests', () => {
    const otp = 'cccaccbtbvkwjjirhcctvdgbahdbijduldcjdurgjgfi';
    const clientId = process.env.CLIENT_ID || '0';
    const apiKey = process.env.API_KEY || '';

    it('Verify', async function () {
        if (clientId === '0' || apiKey.length === 0) {
            return this.skip();
        }

        const response = await YubiKeyOTP.verify(otp, {
            clientId,
            apiKey
        });

        // this should fail because the response is not okay
        assert(!response.valid && response.signatureValid);
    });
});
