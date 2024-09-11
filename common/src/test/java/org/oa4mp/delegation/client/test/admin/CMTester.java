package org.oa4mp.delegation.client.test.admin;

import edu.uiuc.ncsa.security.core.util.BitSetUtil;
import net.sf.json.JSONObject;

import java.math.BigInteger;
import java.util.BitSet;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/14/16 at  9:29 AM
 */
public class CMTester {
    public static void main(String[] args){
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("dn_state",1);
        System.out.println(jsonObject);
        BigInteger bigInteger = new BigInteger("11100",2);
        System.out.println( new BigInteger("111110",2));
        System.out.println( new BigInteger("100000",2));
        System.out.println(bigInteger);
        int n = 28;
        BitSet bs = BitSet.valueOf(new long[]{n});
        BitSet bs1 = BitSet.valueOf(new long[]{16L});
        System.out.println("28->" + bs);
        System.out.println("16->" + bs1);
        bs.and(bs1);
        System.out.println("and:" + bs);
        // or compress
        BitSet bs62 = BitSet.valueOf(new long[]{62}); // all 1's except zeroth
        BitSet bs32 = BitSet.valueOf(new long[]{32}); // only last one

        System.out.println("62 = " + bs62);
        System.out.println("or 62 = " + BitSetUtil.orCompress(bs62));
        System.out.println("and 62 = " + BitSetUtil.andCompress(bs62));
        System.out.println("or 32 = " + BitSetUtil.orCompress(bs32));
        System.out.println("and 32 = " + BitSetUtil.andCompress(bs32));
        System.out.println("and 1 = " + BitSetUtil.andCompress(BitSet.valueOf(new long[]{1})));
        System.out.println("or 2 = " + BitSetUtil.orCompress(BitSet.valueOf(new long[]{2})));
        System.out.println("to int " + BitSetUtil.toInt(bs62));

    }

}
