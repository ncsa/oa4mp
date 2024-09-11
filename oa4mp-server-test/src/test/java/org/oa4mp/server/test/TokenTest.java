package org.oa4mp.server.test;

import org.oa4mp.delegation.common.token.AccessToken;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import org.oa4mp.delegation.common.token.TokenForge;
import org.oa4mp.delegation.common.token.Verifier;
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
        assert 0 > ag.getLifetime();
        assert 0 > ag.getIssuedAt();

        AccessToken at = tf.getAccessToken();
        assert 0 > at.getLifetime();
        assert 0 > at.getIssuedAt();
        
        Verifier v = tf.getVerifier();
        assert 0 > v.getLifetime();
        assert 0 > v.getIssuedAt();

    }


}
