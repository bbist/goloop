/*
 * Copyright 2022 ICON Foundation
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

 package foundation.icon.test.cases;

 import foundation.icon.icx.IconService;
 import foundation.icon.icx.transport.http.HttpProvider;
 import foundation.icon.test.common.Constants;
 import foundation.icon.test.common.Env;
 import foundation.icon.test.common.TestBase;
 import foundation.icon.test.common.TransactionHandler;
 import foundation.icon.test.score.ChainScore;

import org.junit.jupiter.api.BeforeAll;
 import org.junit.jupiter.api.Tag;
 import org.junit.jupiter.api.Test;
 
 import java.math.BigInteger;
 import java.security.SecureRandom;
import java.util.Arrays;
 
 import static foundation.icon.test.common.Env.LOG;
 import static org.junit.jupiter.api.Assertions.assertEquals;
 import static org.junit.jupiter.api.Assertions.assertTrue;
 
 @Tag(Constants.TAG_JAVA_SCORE)
 public class BN256Test extends TestBase {
    private static Env.Node node = Env.nodes[0];
    private static IconService iconService;
    private static TransactionHandler txHandler;
     private static ChainScore chainScore;
     private static SecureRandom secureRandom;
 
     private byte[] getRandomBytes(int size) {
         byte[] bytes = new byte[size];
         secureRandom.nextBytes(bytes);
         bytes[0] = 0; // make positive
         return bytes;
     }
 
     @BeforeAll
     static void init() throws Exception {
        Env.Channel channel = node.channels[0];
        Env.Chain chain = channel.chain;
        iconService = new IconService(new HttpProvider(channel.getAPIUrl(Env.testApiVer)));
        txHandler = new TransactionHandler(iconService, chain);
        secureRandom = new SecureRandom();
        chainScore = new ChainScore(txHandler); 
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

    static class Scalar {
        public BigInteger v;
        Scalar(BigInteger v) {
            this.v = v;
        }
        public static Scalar decode(byte[] r) {
            assertEquals(32, r.length, "Scalar: a scalar should be 32 bytes");
            return new Scalar(new BigInteger(1, r));
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
            assertEquals(64, r.length, "G1Point: a G1Point should be 64 bytes");
            return new G1Point(
                    new BigInteger(1, Arrays.copyOfRange(r, 0, 32)),
                    new BigInteger(1, Arrays.copyOfRange(r, 32, 64)));
        }
        public byte[] encode() {
            return ByteUtil.encodeInto64Bytes(x.toByteArray(), y.toByteArray());
        }
        public String toString() {
            return "("+ x + "," + y + ")";
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
        public String toString() {
            return "["+
            "("+ xi + "," + xr + ")"+ "," +
            "("+ yi + "," + yr + ")"+
            "]";
        }
    }

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
    private static String toHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

     @Test
     public void bn256Add() throws Exception {
        G1Point g = new G1Point(BigInteger.valueOf(1), BigInteger.valueOf(2));
        G1Point t = new G1Point(
            new BigInteger("1368015179489954701390400359078579693043519447331113978918064868415326638035"),
            new BigInteger("9918110051302171585080402603319702774565515993150576347155970296011118125764"));
        
        G1Point r = new G1Point(
            new BigInteger("3353031288059533942658390886683067124040920775575537747144343083137631628272"),
            new BigInteger("19321533766552368860946552437480515441416830039777911637913418824951667761761"));
    
        byte[] input = ByteUtil.concat(g.encode(), t.encode());
        LOG.info("bn256Add.input: " + toHex(input));
        byte[] res = chainScore.bn256("add", input);
        

        G1Point p = G1Point.decode(res);
        assertTrue(r.x.equals(p.x) && r.y.equals(p.y), "testBN256PointAddition - FAIL");
     }

     @Test
     public void bn256Mul() throws Exception {
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

        byte[] input, res;

        input = ByteUtil.concat(g.encode(), scalar.encode());
        LOG.info("bn256Mul.input1: " + toHex(input));

        res = chainScore.bn256("mul", input);
        G1Point smg = G1Point.decode(res);
        assertTrue(smg.x.equals(r_smg.x) && smg.y.equals(r_smg.y), "testBN256PointMultiplication - FAIL 1");
        
        input = ByteUtil.concat(t.encode(), scalar.encode());
        LOG.info("bn256Mul.input2: " + toHex(input));

        res = chainScore.bn256("mul", input);
        G1Point smt = G1Point.decode(res);
        assertTrue(smt.x.equals(r_smt.x) && smt.y.equals(r_smt.y), "testBN256PointMultiplication - FAIL 2");
     }

     @Test
     public void bn256Pairing() throws Exception {

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

        byte[] input = ByteUtil.concat(
            ByteUtil.concat(p1G1.encode(), p1G2.encode()), 
            ByteUtil.concat(p2G1.encode(), p2G2.encode()));

        LOG.info("bn256Pairing.input: " + toHex(input));

        byte[] res = chainScore.bn256("pairing", input);
        assertTrue(res.length > 0 && res[0] > 0, "testBN256PairingCheck - FAIL");
     }

     @Test
     public void testBN256VerifyZKSNARKProof() throws Exception {
        Verifier verifier = new Verifier(chainScore);

        BigInteger[] pi_a = new BigInteger[]{
            new BigInteger("16684022669680673830453515165700674963395232964351010764834083530203445109883"),
            new BigInteger("3028653021776122635395655268800380758847184970920215291549528336445823580943"),
            new BigInteger("1")
    };
        BigInteger[][] pi_b = new BigInteger[][]{
            new BigInteger[]{
                new BigInteger("16019545435286550732862207991613991460472243741127702690400226044408598026704"),
                new BigInteger("8515431580211441608129889527794713967398377015383786722157507682544588806615")
            },
            new BigInteger[]{
                new BigInteger("11104827099225138394242132003389600292544842043312240553983907723092885530843"),
                new BigInteger("11964501106330363136302200310505428406875465673037254434199863395922994591422")
            },
            new BigInteger[]{
                new BigInteger("1"),
                new BigInteger("0")
            },
        };
        BigInteger[] pi_c = new BigInteger[]{
            new BigInteger("21566816309872827151305933445654274507100348952154766944469977942242463769352"),
            new BigInteger("11846556420768311443272036570527259353015618036675442287342448082841616094779"),
            new BigInteger("1")
        };
        BigInteger[] pub_input = new BigInteger[]{
            new BigInteger("7713112592372404476342535432037683616424591277138491596200192981572885523208")
        };

        boolean res = verifier.verifyProof(pi_a, pi_b, pi_c, pub_input);
        assertTrue(res, "Pairing check failed!");
    }

        /* ------------------------------------------------------------------------------------- */

        static class Pairing {
            ChainScore chainScore;

            Pairing(ChainScore chainScore) {
                this.chainScore = chainScore;
            }

            public G1Point P1() {
                return new G1Point(
                        new BigInteger("1"),
                        new BigInteger("2")
                );
            }
    
            public G2Point P2() {
                // Original code point
                return new G2Point(
                        new BigInteger("11559732032986387107991004021392285783925812861821192530917403151452391805634"),
                        new BigInteger("10857046999023057135944570762232829481370756359578518086990519993285655852781"),
                        new BigInteger("4082367875863433681332203403145435568316851327593401208105741076214120093531"),
                        new BigInteger("8495653923123431417604973247489272438418190587263600148770280649306958101930")
                    );
            }
    
            public G1Point negate(G1Point p) {
                // The prime q in the base field F_q for G1
                BigInteger q = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");
                if (p.x.equals(BigInteger.ZERO) && p.y.equals(BigInteger.ZERO)) {
                    return new G1Point(
                            new BigInteger("0"),
                            new BigInteger("0")
                    );
                }
                return new G1Point(
                        p.x,
                        q.subtract(p.y.mod(q))
                );
            }
    
    
    
            public G1Point addition(G1Point p1, G1Point p2) throws Exception {
                byte[] res = chainScore.bn256("add", ByteUtil.concat(p1.encode(), p2.encode()));
                return G1Point.decode(res);
            }
    
            public G1Point scalar_mul(G1Point p, Scalar s) throws Exception {
                byte[] res = chainScore.bn256("mul", ByteUtil.concat(p.encode(), s.encode()));
                return G1Point.decode(res);
            }
    
            public boolean pairing(G1Point[] p1, G2Point[] p2) throws Exception {
                assertTrue(p1.length == p2.length, "Pairing: G1 and G2 points must have same length");
                assertTrue(p1.length > 0, "Paring: Must have some points");
                byte[] arg = new byte[]{};
                for (int i=0; i < p1.length; i++) {
                    byte[] tmp = ByteUtil.concat(p1[i].encode(), p2[i].encode());
                    arg = ByteUtil.concat(arg, tmp);
                }
                LOG.info("pairing.input: " + toHex(arg));
                byte[] res = chainScore.bn256("pairing", arg);
                return res[0] == 1;
            }
    
            public boolean pairingProd2(G1Point a1, G2Point a2, G1Point b1, G2Point b2) throws Exception {
                G1Point[] p1 = new G1Point[]{a1, b1};
                G2Point[] p2 = new G2Point[]{a2, b2};
                return pairing(p1, p2);
            }
    
            public boolean pairingProd3(G1Point a1, G2Point a2, G1Point b1, G2Point b2, G1Point c1, G2Point c2) throws Exception {
                G1Point[] p1 = new G1Point[]{a1, b1, c1};
                G2Point[] p2 = new G2Point[]{a2, b2, c2};
                return pairing(p1, p2);
            }
    
            public boolean pairingProd4(G1Point a1, G2Point a2, G1Point b1, G2Point b2, G1Point c1, G2Point c2, G1Point d1, G2Point d2) throws Exception {
                G1Point[] p1 = new G1Point[]{a1, b1, c1, d1};
                G2Point[] p2 = new G2Point[]{a2, b2, c2, d2};
                return pairing(p1, p2);
            }
    
        }
    
        static class Verifier {
            static class VerifyingKey {
                G1Point alfa1;
                G2Point beta2;
                G2Point gamma2;
                G2Point delta2;
                
                G1Point[] IC;
            }
            
            static class Proof {
                G1Point A;
                G2Point B;
                G1Point C;
            }

            ChainScore chainScore;
            Verifier(ChainScore chainScore) {
                this.chainScore = chainScore;
            }
    
            public VerifyingKey verifyingKey () {
                VerifyingKey vk = new VerifyingKey();
                vk.alfa1 = new G1Point(
                        new BigInteger("6244961780046620888039345106890105326735326490660670538171427260567041582118"),
                        new BigInteger("9345530074574832515777964177156498988936486542424817298013748219694852051085")
                );
    
                vk.beta2 = new G2Point(
                            new BigInteger("2818280727920019509567344333433040640814847647252965574434688845111015589444"),
                            new BigInteger("2491450868879707184707638923318620824043077264425678122529022119991361101584"),
                            new BigInteger("5029766152948309994503689842780415913659475358303615599223648363828913323263"),
                            new BigInteger("2351008111262281888427337816453804537041498010110846693783231450896493019270")
                        );
    
                vk.gamma2 = new G2Point(
                            new BigInteger("11559732032986387107991004021392285783925812861821192530917403151452391805634"),
                            new BigInteger("10857046999023057135944570762232829481370756359578518086990519993285655852781"),
                            new BigInteger("4082367875863433681332203403145435568316851327593401208105741076214120093531"),
                            new BigInteger("8495653923123431417604973247489272438418190587263600148770280649306958101930")
                        );
    
                vk.delta2 = new G2Point(
                            new BigInteger("20357583894981042724041147112728663642192389767532790379586807642603211339296"),
                            new BigInteger("16724459956898194420001774771107011251121183644400113420009731464596132523544"),
                            new BigInteger("16237331308709056395953700405451681465556343609310773522173256536156022093405"),
                            new BigInteger("3391378266105643470740467819376339353336154378345751297020149225371500106870")
                        );
    
                vk.IC = new G1Point[] {
                    new G1Point( 
                        new BigInteger("3318215850506904344917620945683151527416225208972147541837352858560867617664"),
                        new BigInteger("11747151111802793062439135468089529579175934281607584242945730191491913853935")
                    ),
                    
                    new G1Point( 
                        new BigInteger("17917913212281490319834384310170467506722893907782768625202003038096247318861"),
                        new BigInteger("11930672168320499446324697817074991233097854569509354085385760632603596119358")
                    ),
                    
                };
    
                return vk;
            }
    
            public int verify(BigInteger[] input, Proof proof) throws Exception {
                Pairing pairing = new Pairing(chainScore);
                BigInteger snark_scalar_field = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
                VerifyingKey vk = verifyingKey();
                assertEquals(vk.IC.length, input.length + 1, "verifier-bad-input");
                // Compute the linear combination vk_x
                G1Point vk_x = new G1Point(BigInteger.ZERO, BigInteger.ZERO);
                for (int i=0; i<input.length; i++) {
                    assertTrue(input[i].compareTo(snark_scalar_field) < 0, "verifier-gte-snark-scalar-field");
                    vk_x = pairing.addition(vk_x, pairing.scalar_mul(vk.IC[i+1], new Scalar(input[0])));
                }
                vk_x = pairing.addition(vk_x, vk.IC[0]);
                if (!pairing.pairingProd4(pairing.negate(proof.A), proof.B, vk.alfa1, vk.beta2, vk_x, vk.gamma2, proof.C, vk.delta2)) {
                    return 1;
                }
                return 0;
            }
    
            // @External(readonly = true)
            public boolean verifyProof(BigInteger[] a, BigInteger[][] b, BigInteger[] c, BigInteger[] input) throws Exception {
                Proof proof = new Proof();
                proof.A = new G1Point(a[0], a[1]);
                proof.B = new G2Point(b[0][0], b[0][1], b[1][0], b[1][1]);
                proof.C = new G1Point(c[0], c[1]);
    
                // TODO: Verify if copying is necessary
                return verify(input, proof) == 0;
            }
        }
    
        /* ------------------------------------------------------------------------------------- */
        
 }
 