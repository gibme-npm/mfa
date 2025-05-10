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

import { randomBytes } from 'crypto';
import Base32 from '@gibme/base32';

export class Secret {
    public readonly buffer: Buffer;

    /**
     * Constructs a new instance of an OTP secret
     *
     * @param configOrSeed if a string, base32 decoding will be used
     */
    constructor (configOrSeed: Partial<Secret.Options> | string = {}) {
        if (typeof configOrSeed === 'string') {
            configOrSeed = { secret: configOrSeed } as Partial<Secret.Options>;
        }

        configOrSeed.size ??= 20;

        if (typeof configOrSeed.secret === 'string') {
            this.buffer = Base32.decode(configOrSeed.secret.replace(/ /g, ''));
        } else if (configOrSeed.secret) {
            this.buffer = configOrSeed.secret;
        } else {
            this.buffer = randomBytes(configOrSeed.size);
        }
    }

    /**
     * Dumps the secret to a string representation
     *
     * @param encoding
     */
    public toString (encoding: BufferEncoding | 'base32' = 'base32'): string {
        if (encoding === 'base32') {
            return Base32.encode(this.buffer, false);
        }

        return this.buffer.toString(encoding);
    }
}

export namespace Secret {
    export type Options = {
        /**
         * The secret seed
         *
         * If a string is supplied, `secretEncoding` is used to load the secret
         */
        secret: string | Buffer;
        /**
         * The byte size of the seed
         * @default 20
         */
        size: number;
    }
}

export default Secret;
