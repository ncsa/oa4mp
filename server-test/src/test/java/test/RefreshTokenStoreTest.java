package test;

import org.oa4mp.server.test.TestUtils;
import org.oa4mp.server.loader.oauth2.storage.RefreshTokenStore;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;
import org.oa4mp.delegation.common.token.impl.TokenFactory;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import org.oa4mp.delegation.common.token.RefreshToken;
import org.oa4mp.delegation.server.OA2TokenForge;
import edu.uiuc.ncsa.security.util.TestBase;

import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/25/14 at  11:29 AM
 */
public class RefreshTokenStoreTest extends TestBase {
    public long EXPIRES_IN = 10000L;

    public void testFS() throws Exception {
        testRT(TestUtils.getFsStoreProvider().getTransactionStore(), TestUtils.getFsStoreProvider().getClientStore());
    }

    public void testMYSQL() throws Exception {
        testRT(TestUtils.getMySQLStoreProvider().getTransactionStore(),TestUtils.getMySQLStoreProvider().getClientStore());
    }

    public void testMemStore() throws Exception {
        testRT(TestUtils.getMemoryStoreProvider().getTransactionStore(), TestUtils.getMemoryStoreProvider().getClientStore());
    }

    public void testPG() throws Exception {
        testRT(TestUtils.getPgStoreProvider().getTransactionStore(), TestUtils.getPgStoreProvider().getClientStore());
    }

    public void testDerby() throws Exception {
         testRT(TestUtils.getDerbyStoreProvider().getTransactionStore(), TestUtils.getDerbyStoreProvider().getClientStore());
     }

    public void testRT(TransactionStore tStore, ClientStore clientStore) throws Exception {
        if (!(tStore instanceof RefreshTokenStore)) {
            // fail here if can't cast
            throw new IllegalStateException(" The store " + tStore.getClass().getSimpleName() + " is not of a type RefreshTokenStore");
        }

        RefreshTokenStore rts = (RefreshTokenStore) tStore;
        OA2ServiceTransaction st2 = (OA2ServiceTransaction) tStore.create();

        OA2TokenForge tf2 = new OA2TokenForge("http://localhost/test/" + getRandomString() + "/");

        RefreshToken rt = tf2.getRefreshToken();
        st2.setRefreshToken(rt);
        // the auth grant is used to retrieve this later and should in this case just be set to the identifier.
        AuthorizationGrant ag = TokenFactory.createAG(st2.getIdentifierString());
        OA2Client client = new OA2Client(BasicIdentifier.randomID());
        clientStore.save(client);
        st2.setClient(client);
        st2.setAuthorizationGrant(ag);
        st2.setRefreshTokenLifetime(EXPIRES_IN);
        st2.setAuthTime(new Date());
        tStore.save(st2);

        OA2ServiceTransaction testST = rts.get(rt);
        assert testST.equals(st2) : " created transaction is not fetched faithfully from the store";
        // get another one and retry since we have to be able to show the store can handle updating the refresh token
        rt = tf2.getRefreshToken();
        st2.setRefreshToken(rt);
        st2.setRefreshTokenValid(false);

        tStore.save(st2);
        assert rts.get(rt).equals(st2) : " updating refresh token fails.";
        tStore.remove(st2.getIdentifier());
        clientStore.remove(client.getIdentifier());

    }

}
