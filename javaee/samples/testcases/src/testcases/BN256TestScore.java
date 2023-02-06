package testcases;

import java.math.BigInteger;
import java.util.Arrays;

import score.Context;
import score.annotation.External;

public class BN256TestScore {

    static class Scalar {
        public BigInteger v;
        Scalar(BigInteger v) {
            this.v = v;
        }
        public static Scalar decode(byte[] r) {
            Context.require(r.length == 32, "Scalar: a scalar should be 32 bytes");
            return new Scalar(new BigInteger(r));
        }
        public byte[] encode() {
            return ByteUtil.encodeInto32Bytes(v.toByteArray());
        }
    }

    static class G1Point {
        public BigInteger x;
        public BigInteger y;
        G1Point(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }
        public static G1Point decode(byte[] r) {
            Context.require(r.length == 64, "G1Point: a G1Point should be 64 bytes");
            return new G1Point(
                new BigInteger(Arrays.copyOfRange(r, 0, 32)),
                new BigInteger(Arrays.copyOfRange(r, 32, 64)));
        }
        public byte[] encode() {
            return ByteUtil.encodeInto64Bytes(x.toByteArray(), y.toByteArray());
        }
    }
    
    static class G2Point {
        public BigInteger xi;
        public BigInteger xr;
        public BigInteger yi;
        public BigInteger yr;
        G2Point(BigInteger xi, BigInteger xr, BigInteger yi, BigInteger yr) {
            this.xi = xi;
            this.xr = xr;
            this.yi = yi;
            this.yr = yr;
        }
        public byte[] encode() {
            byte[] x = ByteUtil.encodeInto64Bytes(xi.toByteArray(), xr.toByteArray());
            byte[] y = ByteUtil.encodeInto64Bytes(yi.toByteArray(), yr.toByteArray());
            return ByteUtil.concat(x, y);
        }
    }


    @External
    public void test() {
        testBN256PointAddition();
        testBN256PointMultiplication();
        testBN256PairingCheck();
    }

    public void testBN256PointAddition() {
        
        G1Point g = new G1Point(BigInteger.valueOf(1), BigInteger.valueOf(2));
        G1Point t = new G1Point(
            new BigInteger("1368015179489954701390400359078579693043519447331113978918064868415326638035"),
            new BigInteger("9918110051302171585080402603319702774565515993150576347155970296011118125764"));
        
        G1Point r = new G1Point(
            new BigInteger("3353031288059533942658390886683067124040920775575537747144343083137631628272"),
            new BigInteger("19321533766552368860946552437480515441416830039777911637913418824951667761761"));
    
        byte[] res;        
        res = Context.bn256("add", ByteUtil.concat(g.encode(), t.encode()));
        G1Point p = G1Point.decode(res);
        Context.require(r.x.equals(p.x) && r.y.equals(p.y));

        Context.println("testBN256PointAddition - OK");
    }

    public void testBN256PointMultiplication() {

        Scalar scalar = new Scalar(BigInteger.valueOf(100));

        G1Point g = new G1Point(BigInteger.valueOf(1), BigInteger.valueOf(2));
        G1Point t = new G1Point(
            new BigInteger("3353031288059533942658390886683067124040920775575537747144343083137631628272"),
            new BigInteger("19321533766552368860946552437480515441416830039777911637913418824951667761761"));

        G1Point r_smg = new G1Point(
            new BigInteger("8464813805670834410435113564993955236359239915934467825032129101731355555480"),
            new BigInteger("15805858227829959406383193382434604346463310251314385567227770510519895659279"));

        G1Point r_smt = new G1Point(
            new BigInteger("11209121543473762808410294927400266515795855041300595717510895007300042510192"),
            new BigInteger("7999428731060228165396639251944663702040728315123318054823970324406778903091"));

        byte[] res;

        res = Context.bn256("mul", ByteUtil.concat(g.encode(), scalar.encode()));
        G1Point smg = G1Point.decode(res);
        Context.require(smg.x.equals(r_smg.x) && smg.y.equals(r_smg.y));
        
        res = Context.bn256("mul", ByteUtil.concat(t.encode(), scalar.encode()));
        G1Point smt = G1Point.decode(res);
        Context.require(smt.x.equals(r_smt.x) && smt.y.equals(r_smt.y));

        Context.println("testBN256PointMultiplication - OK");
    }
    
    public void testBN256PairingCheck() {

        G1Point p1G1 = new G1Point(
            new BigInteger("1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f59", 16), 
            new BigInteger("3034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41", 16));

        G2Point p1G2 = new G2Point(
            new BigInteger("04bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a41678", 16), 
            new BigInteger("209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf7", 16), 
            new BigInteger("120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550", 16),
            new BigInteger("2bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d", 16)
        );

        G1Point p2G1 = new G1Point(
            new BigInteger("111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c", 16), 
            new BigInteger("2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411", 16));

        G2Point p2G2 = new G2Point(
            new BigInteger("1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed", 16), 
            new BigInteger("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2", 16), 
            new BigInteger("12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa", 16),
            new BigInteger("090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b", 16)
        );

        byte[] pairs = ByteUtil.concat(
            ByteUtil.concat(p1G1.encode(), p1G2.encode()), 
            ByteUtil.concat(p2G1.encode(), p2G2.encode()));

        byte[] res = Context.bn256("pairing", pairs);
        Context.require(res.length > 0 && res[0] > 0, "Pairing check failed!");

        Context.println("testBN256PairingCheck - OK");
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

        static byte[] encodeInto64Bytes(byte[] w1, byte[] w2) {
            byte[] res = new byte[64];
    
            w1 = stripLeadingZeroes(w1);
            w2 = stripLeadingZeroes(w2);
    
            System.arraycopy(w1, 0, res, 32 - w1.length, w1.length);
            System.arraycopy(w2, 0, res, 64 - w2.length, w2.length);
    
            return res;
        }

        static byte[] encodeInto32Bytes(byte[] w) {
            byte[] res = new byte[32];
            w = stripLeadingZeroes(w);
            System.arraycopy(w, 0, res, 32 - w.length, w.length);
            return res;
        }
        
        
        static byte[] concat(byte[] w1, byte[] w2) {
            byte[] res = new byte[w1.length+w2.length];
            System.arraycopy(w1, 0, res, 0, w1.length);
            System.arraycopy(w2, 0, res, w1.length, w2.length);
            return res;
        }
    }
    
}
