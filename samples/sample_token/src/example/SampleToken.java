package example;

import avm.Address;
import avm.Blockchain;

import foundation.icon.ee.tooling.abi.EventLog;
import foundation.icon.ee.tooling.abi.External;
import foundation.icon.ee.tooling.abi.OnInstall;
import foundation.icon.ee.tooling.abi.Payable;

import java.math.BigInteger;

//@InterfaceScore
//interface TokenFallbackInterface {
//    void tokenFallback(Address from, BigInteger value, byte[] data);
//}

public class SampleToken
{
    private final String name;
    private final String symbol;
    private final int decimals;
    private final BigInteger totalSupply;

    private SampleToken(String name, String symbol, BigInteger decimals, BigInteger initialSupply) {
        this.name = name;
        this.symbol = symbol;
        this.decimals = decimals.intValue();

        // decimals must be larger than 0 and less than 21
        Blockchain.require(this.decimals >= 0);
        Blockchain.require(this.decimals <= 21);

        // initialSupply must be larger than 0
        Blockchain.require(initialSupply.compareTo(BigInteger.ZERO) >= 0);

        if (initialSupply.compareTo(BigInteger.ZERO) > 0) {
            //*** NOTE: #pow() is not implemented in the shadow BigInteger
            //#ORIG
            //this.totalSupply = initialSupply.multiply(BigInteger.TEN.pow(this.decimals));
            //#TEMP
            BigInteger exp = BigInteger.ONE;
            for (int i = 0; i < this.decimals; i++) {
                exp = exp.multiply(BigInteger.TEN);
            }
            this.totalSupply = initialSupply.multiply(exp);
            //#
        } else {
            this.totalSupply = BigInteger.ZERO;
        }

        // set the initial balance of the owner
        TokenStore.putBalance(Blockchain.getOrigin(), this.totalSupply);
    }

    private static SampleToken token;

    @OnInstall
    public static void init(String name,
                            String symbol,
                            BigInteger decimals,
                            BigInteger initialSupply) {
        token = new SampleToken(name, symbol, decimals, initialSupply);
    }

    @Payable
    public static void fallback() {
    }

    @External(readonly=true)
    public static String name() {
        return token.name;
    }

    @External(readonly=true)
    public static String symbol() {
        return token.symbol;
    }

    @External(readonly=true)
    public static int decimals() {
        return token.decimals;
    }

    @External(readonly=true)
    public static BigInteger totalSupply() {
        return token.totalSupply;
    }

    @External(readonly=true)
    public static BigInteger balanceOf(Address _owner) {
        return TokenStore.getBalance(_owner);
    }

    @External
    public static void transfer(Address _to, BigInteger _value) {
        Address _from = Blockchain.getCaller();
        BigInteger fromBalance = TokenStore.getBalance(_from);
        BigInteger toBalance = TokenStore.getBalance(_to);

        // check some basic requirements
        Blockchain.require(_value.compareTo(BigInteger.ZERO) >= 0);
        Blockchain.require(fromBalance.compareTo(_value) >= 0);

        TokenStore.putBalance(_from, fromBalance.subtract(_value));
        TokenStore.putBalance(_to, toBalance.add(_value));

        /*
         * If the recipient is SCORE,
         *   then calls `tokenFallback` to hand over control.
        if (_to.isContract()) {
            TokenFallbackInterface recipientScore = Blockchain.getInterfaceScore(_to, TokenFallbackInterface.class)
            recipientScore.tokenFallback(_from, _value, _data)
        }
         */

        Transfer(_from, _to, _value, "Some data".getBytes());
    }

    @EventLog(indexed=3)
    private static void Transfer(Address from, Address to, BigInteger value, byte[] data) {}
}
