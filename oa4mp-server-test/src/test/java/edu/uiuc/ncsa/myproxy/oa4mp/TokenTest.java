package edu.uiuc.ncsa.myproxy.oa4mp;

import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.delegation.token.Verifier;
import edu.uiuc.ncsa.security.util.TestBase;
import org.junit.Test;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 18, 2011 at  9:12:00 AM
 */
public class TokenTest extends TestBase {

    public TestStoreProviderInterface getTSProvider() {
        return TestUtils.getMemoryStoreProvider();
    }

    @Test
    public void testToken() throws Exception {
        // At initialization all of the times should be negative so we can
        // check later if they have been set right.
        TokenForge tf = getTSProvider().getTokenForge();
        AuthorizationGrant ag = tf.getAuthorizationGrant();
        assert 0 > ag.getExpiresAt();
        assert 0 > ag.getIssuedAt();

        AccessToken at = tf.getAccessToken();
        assert 0 > at.getExpiresAt();
        assert 0 > at.getIssuedAt();
        
        Verifier v = tf.getVerifier();
        assert 0 > v.getExpiresAt();
        assert 0 > v.getIssuedAt();

    }


}
