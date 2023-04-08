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

import { randomBytes } from 'crypto';
import Base32 from '@gibme/base32';

export type BufferEncodingLike = BufferEncoding | 'base32';

export interface SecretOptions {
    /**
     * The secret seed
     *
     * If a string is supplied, `secretEncoding` is used to load the secret
     */
    secret: string | Buffer;
    /**
     * The encoding of the secret seed
     * @default base32
     */
    secretEncoding: BufferEncodingLike;
    /**
     * The byte size of the seed
     * @default 20
     */
    size: number;
}

export default class Secret {
    public readonly buffer: Buffer;

    /**
     * Constructs a new instance of an OTP secret
     *
     * @param configOrSeed if a string, base32 decoding will be used
     */
    constructor (configOrSeed: Partial<SecretOptions> | string = {}) {
        if (typeof configOrSeed === 'string') {
            configOrSeed = { secret: configOrSeed };
        }

        const _config = configOrSeed as any;

        _config.size ||= 20;
        _config.secretEncoding ||= 'base32';

        if (_config.secret instanceof Buffer) {
            this.buffer = _config.secret;
        } else if (_config.secret) {
            this.buffer = Base32.decode(_config.secret);
        } else {
            this.buffer = randomBytes(_config.size);
        }
    }

    /**
     * Dumps the secret to a string representation
     *
     * @param encoding
     */
    public toString (encoding: BufferEncodingLike = 'base32'): string {
        if (encoding === 'base32') {
            return Base32.encode(this.buffer, false);
        }

        return this.buffer.toString(encoding);
    }
}
