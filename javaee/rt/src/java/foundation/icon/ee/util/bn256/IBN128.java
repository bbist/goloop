package foundation.icon.ee.util.bn256;

import java.math.BigInteger;

public class IBN128 {

    public static BN128<Fp> Fp(BigInteger x, BigInteger y) {
        BN128<Fp> r = BN128Fp.create(x.toByteArray(), y.toByteArray());
        if (r == null)
            throw new IllegalArgumentException("Invalid Fp point (" + x + "," + y + ")!");
        return r;
    }

    public static BN128<Fp2> Fp2(
            BigInteger xa, BigInteger xb,
            BigInteger ya, BigInteger yb) {
        BN128<Fp2> r = BN128Fp2.create(
                xa.toByteArray(), xb.toByteArray(),
                ya.toByteArray(), yb.toByteArray());
        if (r == null)
            throw new IllegalArgumentException("Invalid Fp2 point ( " + xa + "i*" + xb + ", " + ya + "i*" + yb + " )!");
        return r;
    }

    public static BN128G1 G1(BigInteger x, BigInteger y) {
        BN128G1 r = BN128G1.create(x.toByteArray(), y.toByteArray());
        if (r == null)
            throw new IllegalArgumentException("Invalid G1 point (" + x + "," + y + ")!");
        return r;
    }

    public static BN128G2 G2(
            BigInteger xa, BigInteger xb,
            BigInteger ya, BigInteger yb) {
        BN128G2 r = BN128G2.create(
                xa.toByteArray(), xb.toByteArray(),
                ya.toByteArray(), yb.toByteArray());
        if (r == null)
            throw new IllegalArgumentException("Invalid G2 point ( " + xa + "i*" + xb + ", " + ya + "i*" + yb + " )!");
        return r;
    }

    public static void pairing() {
    }
}
