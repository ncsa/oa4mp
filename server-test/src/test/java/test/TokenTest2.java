package test;

import org.oa4mp.server.test.TokenTest;
import org.oa4mp.delegation.server.OA2TokenForge;
import org.junit.Test;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/28/16 at  10:53 AM
 */
public class TokenTest2 extends TokenTest {
 @Test
    public void refreshTokenTest() throws  Exception{
     OA2TokenForge tf =(OA2TokenForge) getTSProvider().getTokenForge();
     System.out.println("RT=" + tf.getRefreshToken());
 }
}
