/*
 * Copyright 2019 ICON Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package foundation.icon.ee.util;

import foundation.icon.ee.util.bls12381.BLS12381;
import foundation.icon.ee.util.bn256.*;
import foundation.icon.ee.util.xxhash.XxHash;
import i.RuntimeAssertionError;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Crypto {
    public static final int BN256_PAIR_SIZE = 192;

    public static byte[] sha3_256(byte[] msg) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA3-256");
            return digest.digest(msg);
        } catch (NoSuchAlgorithmException e) {
            throw RuntimeAssertionError.unexpected(e);
        }
    }

    public static byte[] sha256(byte[] msg) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(msg);
        } catch (NoSuchAlgorithmException e) {
            throw RuntimeAssertionError.unexpected(e);
        }
    }

    public static byte[] keccack256(byte[] msg) {
        Keccak.DigestKeccak keccak = new Keccak.Digest256();
        keccak.update(msg);
        return keccak.digest();
    }

    static void require(boolean cond, String msg) {
        if (!cond) {
            throw new IllegalArgumentException(msg);
        }
    }

    public static byte[] hash(String alg, byte[] msg) {
        switch (alg) {
            case "sha-256":
                return sha256(msg);
            case "sha3-256":
                return sha3_256(msg);
            case "keccak-256":
                return keccack256(msg);
            case "xxhash-128":
                return XxHash.hash128(msg);
            case "blake2b-128": {
                var digest = new Blake2bDigest(128);
                digest.update(msg, 0, msg.length);
                var res = new byte[128/8];
                digest.doFinal(res, 0);
                return res;
            }
            case "blake2b-256": {
                var digest = new Blake2bDigest(256);
                digest.update(msg, 0, msg.length);
                var res = new byte[256/8];
                digest.doFinal(res, 0);
                return res;
            }
        }
        throw new IllegalArgumentException("Unsupported algorithm " + alg);
    }

    public static boolean verifySignature(String alg, byte[] msg, byte[] sig, byte[] pk) {
        switch (alg) {
            case "ed25519": {
                require(sig.length == Ed25519.SIGNATURE_SIZE, "invalid signature length");
                require(pk.length == Ed25519.PUBLIC_KEY_SIZE, "invalid public key length");
                return Ed25519.verify(sig, 0, pk, 0, msg, 0, msg.length);
            }
            case "ecdsa-secp256k1": {
                require(msg.length == 32, "the length of message must be 32");
                require(sig.length == 65, "the length of signature must be 65");
                require(pk.length == 33 || pk.length == 65, "invalid public key length");
                var recovered = recoverKey(msg, sig, pk.length==33);
                return Arrays.equals(recovered, pk);
            }
            case "bls12-381-g2": {
                require(pk.length == BLS12381.G1_LEN, "invalid public key length");
                require(sig.length == BLS12381.G2_LEN, "invalid signature length");
                return BLS12381.verifyG2Signature(pk, sig, msg);
            }
        }
        throw new IllegalArgumentException("Unsupported algorithm " + alg);
    }

    public static byte[] recoverKey(String alg, byte[] msg, byte[] sig, boolean compressed) {
        switch (alg) {
            case "ecdsa-secp256k1": {
                require(msg.length == 32, "the length of msgHash must be 32");
                require(sig.length == 65, "the length of signature must be 65");
                return recoverKey(msg, sig, compressed);
            }
        }
        throw new IllegalArgumentException("Unsupported algorithm " + alg);
    }

    public static byte[] aggregate(String type, byte[] prevAgg, byte[] values) {
        switch (type) {
            case "bls12-381-g1": {
                require(prevAgg == null || prevAgg.length == BLS12381.G1_LEN, "invalid prevAgg");
                require(values.length % BLS12381.G1_LEN == 0, "invalid values length");
                return BLS12381.aggregateG1Values(prevAgg, values);
            }
        }
        throw new IllegalArgumentException("Unsupported type " + type);
    }

    public static byte[] recoverKey(byte[] msgHash, byte[] signature, boolean compressed) {
        BigInteger r = BigIntegers.fromUnsignedByteArray(signature, 0, 32);
        BigInteger s = BigIntegers.fromUnsignedByteArray(signature, 32, 32);
        return recoverFromSignature(signature[64], r, s, msgHash, compressed);
    }

    public static byte[] getAddressBytesFromKey(byte[] pubKey) {
        checkArgument(pubKey.length == 33 || pubKey.length == 65, "Invalid key length");
        byte[] uncompressed;
        if (pubKey.length == 33) {
            uncompressed = uncompressKey(pubKey);
        } else {
            uncompressed = pubKey;
        }
        byte[] hash = sha3_256(Arrays.copyOfRange(uncompressed, 1, uncompressed.length));
        byte[] address = new byte[21];
        System.arraycopy(hash, hash.length - 20, address, 1, 20);
        return address;
    }

    private final static X9ECParameters curveParams = CustomNamedCurves.getByName("secp256k1");
    private final static ECDomainParameters curve = new ECDomainParameters(
            curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH());

    private static byte[] uncompressKey(byte[] compKey) {
        ECPoint point = curve.getCurve().decodePoint(compKey);
        byte[] x = point.getXCoord().getEncoded();
        byte[] y = point.getYCoord().getEncoded();
        byte[] key = new byte[x.length + y.length + 1];
        key[0] = 0x04;
        System.arraycopy(x, 0, key, 1, x.length);
        System.arraycopy(y, 0, key, x.length + 1, y.length);
        return key;
    }

    private static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(curve.getCurve()));
        compEnc[0] = (byte) (yBit ? 0x03 : 0x02);
        return curve.getCurve().decodePoint(compEnc);
    }

    private static byte[] recoverFromSignature(int recId, BigInteger r, BigInteger s, byte[] message, boolean compressed) {
        checkArgument(recId >= 0, "recId must be positive");
        checkArgument(r.signum() >= 0, "r must be positive");
        checkArgument(s.signum() >= 0, "s must be positive");

        BigInteger n = curve.getN();
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = r.add(i.multiply(n));
        BigInteger prime = SecP256K1Curve.q;
        if (x.compareTo(prime) >= 0) {
            return null;
        }
        ECPoint ecPoint = decompressKey(x, (recId & 1) == 1);
        if (!ecPoint.multiply(n).isInfinity()) {
            return null;
        }
        BigInteger e = new BigInteger(1, message);
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = rInv.multiply(s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(curve.getG(), eInvrInv, ecPoint, srInv);
        return q.getEncoded(compressed);
    }

    private static void checkArgument(boolean expression, String message) {
        if (!expression) {
            throw new IllegalArgumentException(message);
        }
    }

    public static class ByteUtil {
        public static final byte[] EMPTY_BYTE_ARRAY = new byte[0];
        public static final byte[] ZERO_BYTE_ARRAY = new byte[]{0};
    
        public static int firstNonZeroByte(byte[] data) {
            for (int i = 0; i < data.length; ++i) {
                if (data[i] != 0) {
                    return i;
                }
            }
            return -1;
        }
    
        public static byte[] stripLeadingZeroes(byte[] data) {
    
            if (data == null)
                return null;
    
            final int firstNonZero = firstNonZeroByte(data);
            switch (firstNonZero) {
                case -1:
                    return ZERO_BYTE_ARRAY;
    
                case 0:
                    return data;
    
                default:
                    byte[] result = new byte[data.length - firstNonZero];
                    System.arraycopy(data, firstNonZero, result, 0, data.length - firstNonZero);
    
                    return result;
            }
        }

        private static byte[] encodeInto64Bytes(byte[] w1, byte[] w2) {
            byte[] res = new byte[64];
    
            w1 = stripLeadingZeroes(w1);
            w2 = stripLeadingZeroes(w2);
    
            System.arraycopy(w1, 0, res, 32 - w1.length, w1.length);
            System.arraycopy(w2, 0, res, 64 - w2.length, w2.length);
    
            return res;
        }
    }

    public static byte[] bn256Add(byte[] data) {
        if (data.length != 32 * 4)
            throw new IllegalArgumentException("bn256Add: insufficient input data");

        BN128<Fp> p_a = BN128Fp.create(
            Arrays.copyOfRange(data, 0, 32), Arrays.copyOfRange(data, 32, 64));
        if (p_a == null)
            throw new IllegalArgumentException("bn256Add: invalid G1 point A");
            
        BN128<Fp> p_b = BN128Fp.create(
            Arrays.copyOfRange(data, 64, 96), Arrays.copyOfRange(data, 96, 128));
        if (p_b == null)
            throw new IllegalArgumentException("bn256Add: invalid G1 point B");
        
        BN128<Fp> res = p_a.add(p_b).toEthNotation();
        
        return ByteUtil.encodeInto64Bytes(res.x().bytes(), res.y().bytes());
    }

    public static byte[] bn256Mul(byte[] data) {
        if (data.length != 32 * 3)
            throw new IllegalArgumentException("bn256Mul: insufficient input data");

        BN128<Fp> p = BN128Fp.create(
            Arrays.copyOfRange(data, 0, 32), Arrays.copyOfRange(data, 32, 64));
            
        if (p == null)
            throw new IllegalArgumentException("bn256Add: invalid G1 point P");
        
        BigInteger scalar = new BigInteger(Arrays.copyOfRange(data, 64, 96));

        BN128<Fp> res = p.mul(scalar).toEthNotation();

        return ByteUtil.encodeInto64Bytes(res.x().bytes(), res.y().bytes());
    }

    public static byte[] bn256Pairing(byte[] data) {
        int num_pairs = data.length / BN256_PAIR_SIZE;

        if (data.length % BN256_PAIR_SIZE > 0) {
            throw new IllegalArgumentException("bn256Pairing: invalid input data layout");
        }

        PairingCheck check = PairingCheck.create();
    
        // iterating over all pairs
        for (int i = 0; i < num_pairs; i++) {
            int offset = i * BN256_PAIR_SIZE;

            BN128G1 p1 = BN128G1.create(Arrays.copyOfRange(data, offset, offset+32), Arrays.copyOfRange(data, offset+32, offset+32*2));
            if (p1 == null)
                throw new IllegalArgumentException("bn256Pairing: invalid G1 point: " + i);
            
            BN128G2 p2 = BN128G2.create(
                Arrays.copyOfRange(data, offset+32*2, offset+32*3), Arrays.copyOfRange(data, offset+32*3, offset+32*4), 
                Arrays.copyOfRange(data, offset+32*4, offset+32*5), Arrays.copyOfRange(data, offset+32*5, offset+32*6));
            if (p2 == null)
                throw new IllegalArgumentException("bn256Pairing: invalid G2 point: " + i);
    
            check.addPair(p1, p2);
        }

        check.run();

        return check.result() > 0 ? new byte[]{1} : new byte[]{1};
    }
}
