/**
 * Copyright (C) 2011 Ovea <dev@ovea.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package it.uniroma1.dis.wsngroup.utils;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;

/**
 * http://en.wikipedia.org/wiki/XXTEA
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public final class XXTEA {

	private static final int DELTA = 0x9e3779b9;

	public static IntBuffer encryptInPlace(IntBuffer data, IntBuffer key) {
		if (key.limit() != 4) {
			throw new IllegalArgumentException("XXTEA needs a 128-bits key");
		}
		if (data.limit() < 2) {
			return data;
		}
		int n = data.limit(),
				p,
				rounds = 6 + 52 / data.limit(),
				e,
				y,
				sum = 0;
		int z = data.get(n - 1);
		do {
			sum += DELTA;
			e = (sum >>> 2) & 3;
			for (p = 0; p < n - 1; p++) {
				y = data.get(p + 1);
				z = data.get(p) + (((z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4)) ^ ((sum ^ y) + (key.get((p & 3) ^ e) ^ z)));
				data.put(p, z);
			}
			y = data.get(0);
			z = data.get(n - 1) + (((z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4)) ^ ((sum ^ y) + (key.get((p & 3) ^ e) ^ z)));
			data.put(p, z);
		} while (--rounds > 0);
		data.position(0);
		return data;
	}

	public static int[] encryptInPlace(int[] data, int[] key) {
		encryptInPlace(IntBuffer.wrap(data), IntBuffer.wrap(key));
		return data;
	}

	public static byte[] encryptInPlace(byte[] data, byte[] key) {
		encryptInPlace(ByteBuffer.wrap(data), ByteBuffer.wrap(key));
		return data;
	}

	public static ByteBuffer encryptInPlace(ByteBuffer data, ByteBuffer key) {
		encryptInPlace(data.asIntBuffer(), key.asIntBuffer());
		return data;
	}

	public static IntBuffer encrypt(IntBuffer data, IntBuffer key) {
		int[] copy = new int[data.limit() - data.position()];
		data.get(copy);
		return encryptInPlace(IntBuffer.wrap(copy), key);
	}

	public static int[] encrypt(int[] data, int[] key) {
		return encrypt(IntBuffer.wrap(data), IntBuffer.wrap(key)).array();
	}

	public static ByteBuffer encrypt(ByteBuffer data, ByteBuffer key) {
		byte[] copy = new byte[data.limit() - data.position()];
		data.get(copy);
		return encryptInPlace(ByteBuffer.wrap(copy), key);
	}

	public static byte[] encrypt(byte[] data, byte[] key) {
		return encrypt(ByteBuffer.wrap(data), ByteBuffer.wrap(key)).array();
	}

	public static IntBuffer decryptInPlace(IntBuffer data, IntBuffer key) {
		if (key.limit() != 4) {
			throw new IllegalArgumentException("XXTEA needs a 128-bits key");
		}
		if (data.limit() < 2) {
			return data;
		}
		int z,
		p,
		e,
		y = data.get(0),
		sum = (6 + 52 / data.limit()) * DELTA,
		l = data.limit();
		do {
			e = (sum >>> 2) & 3;
			for (p = data.limit() - 1; p > 0; p--) {
				z = data.get(p - 1);
				y = data.get(p) - (((z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4)) ^ ((sum ^ y) + (key.get((p & 3) ^ e) ^ z)));
				data.put(p, y);
			}
			z = data.get(l - 1);
			y = data.get(0) - (((z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4)) ^ ((sum ^ y) + (key.get((p & 3) ^ e) ^ z)));
			data.put(0, y);
		} while ((sum -= DELTA) != 0);
		data.position(0);
		return data;
	}

	public static int[] decryptInPlace(int[] data, int[] key) {
		decryptInPlace(IntBuffer.wrap(data), IntBuffer.wrap(key));
		return data;
	}

	public static byte[] decryptInPlace(byte[] data, byte[] key) {
		decryptInPlace(ByteBuffer.wrap(data), ByteBuffer.wrap(key));
		return data;
	}

	public static ByteBuffer decryptInPlace(ByteBuffer data, ByteBuffer key) {
		decryptInPlace(data.asIntBuffer(), key.asIntBuffer());
		return data;
	}

	public static IntBuffer decrypt(IntBuffer data, IntBuffer key) {
		int[] copy = new int[data.limit() - data.position()];
		data.get(copy);
		return decryptInPlace(IntBuffer.wrap(copy), key);
	}

	public static int[] decrypt(int[] data, int[] key) {
		return decrypt(IntBuffer.wrap(data), IntBuffer.wrap(key)).array();
	}

	public static ByteBuffer decrypt(ByteBuffer data, ByteBuffer key) {
		byte[] copy = new byte[data.limit() - data.position()];
		data.get(copy);
		return decryptInPlace(ByteBuffer.wrap(copy), key);
	}

	public static byte[] decrypt(byte[] data, byte[] key) {
		return decrypt(ByteBuffer.wrap(data), ByteBuffer.wrap(key)).array();
	}

}