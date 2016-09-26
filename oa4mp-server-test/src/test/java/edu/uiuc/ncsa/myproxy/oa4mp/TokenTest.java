package edu.uiuc.ncsa.myproxy.oa4mp;

import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.util.TestBase;
import org.junit.Test;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 18, 2011 at  9:12:00 AM
 */
public class TokenTest extends TestBase {

    public TestStoreProvider getTSProvider() {
        return TestUtils.getMemoryStoreProvider();
    }

    @Test
    public void testToken() throws Exception {
        TokenForge tf = getTSProvider().getTokenForge();
        System.out.println("AT = " + tf.getAccessToken());
        System.out.println("AG = " + tf.getAuthorizationGrant());
        System.out.println("V = " + tf.getVerifier());
    }


}
