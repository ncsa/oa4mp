package edu.uiuc.ncsa.oauth2.test;

import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.oauth_2_0.OA2TokenForge;
import edu.uiuc.ncsa.security.util.TestBase;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/25/14 at  11:29 AM
 */
public class RefreshTokenStoreTest extends TestBase {
    public long EXPIRES_IN = 10000L;

    public void testFS() throws Exception {
        testRT(TestUtils.getFsStoreProvider().getTransactionStore());
    }

    public void testMYSQL() throws Exception {
        testRT(TestUtils.getMySQLStoreProvider().getTransactionStore());
    }

    public void testMemStore() throws Exception {
        testRT(TestUtils.getMemoryStoreProvider().getTransactionStore());
    }

    public void testPG() throws Exception {
        testRT(TestUtils.getPgStoreProvider().getTransactionStore());
    }


    public void testRT(TransactionStore tStore) throws Exception {
        if (!(tStore instanceof RefreshTokenStore)) {
            // fail here if can't cast
            throw new IllegalStateException("Error: The store " + tStore.getClass().getSimpleName() + " is not of a type RefreshTokenStore");
        }
        RefreshTokenStore rts = (RefreshTokenStore) tStore;
        OA2ServiceTransaction st2 = (OA2ServiceTransaction) tStore.create();

        OA2TokenForge tf2 = new OA2TokenForge("http://localhost/test/");

        RefreshToken rt = tf2.getRefreshToken();
        st2.setRefreshToken(rt);
        // the auth grant is used to retrieve this later and should in this case just be set to the identifier.
        AuthorizationGrant ag = tf2.getAuthorizationGrant(st2.getIdentifierString());

        st2.setAuthorizationGrant(ag);
        st2.setRefreshTokenLifetime(EXPIRES_IN);
        tStore.save(st2);
        OA2ServiceTransaction testST = rts.get(rt);
        assert testST.equals(st2) : "Error: created transaction is not fetched faithfully from the store";
        // get another one and retry since we have to be able to show the store can handle updating the refresh token
        rt = tf2.getRefreshToken();
        st2.setRefreshToken(rt);
        st2.setRefreshTokenValid(false);

        tStore.save(st2);
        assert rts.get(rt).equals(st2) : "Error: updating refresh token fails.";


    }

}
