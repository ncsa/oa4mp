package org.oa4mp.server.test;

import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.derby.DerbyConnectionParameters;
import edu.uiuc.ncsa.security.storage.sql.derby.DerbyConnectionPool;
import edu.uiuc.ncsa.security.util.TestBase;
import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.server.storage.ClientStore;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/26/17 at  3:42 PM
 */
public class NewClientStoreTest extends TestBase {
    public void testFS() throws Exception {
        try {
            testBasic(TestUtils.getFsStoreProvider().getClientStore());
        }catch(Throwable t){
            if(TestUtils.getFsStoreProvider().getClientStore() instanceof SQLStore) {
                SQLStore sqlStore = (SQLStore) TestUtils.getFsStoreProvider().getClientStore();
                DerbyConnectionParameters derbyConnectionParameters = ((DerbyConnectionPool) sqlStore.getConnectionPool()).getConnectionParameters();
                /*
                   If you get an error like "can't register object" and the SQl exception is something like "column oa4mp.XXX does
                   not exist, this means one of
                   (1) The main installed database for OA4MP needs to have the column added to the right table
                   (2) If in a FS (file store) test, this database is created on the fly from the SQL derby file. Is the column there?
                   (3) If The database exists from a previous run, the column will not be added. Either add it directly (you will
                       need to find the right connection string, but if the ont he fly FS test database, just remove it and run again
                   (4) Pay a mind to where this was started. Derby by default will put a file-based SQL store in the current directory, under
                       the username, oa4mp. Remove that.
                 */
                // Might want to look in ~/dev/ncsa-git/oa4mp/oa4mp if this really gets confused and bombs in IntelliJ
                // That would be a default location for the on-the-fly Derby file store test.
                // Also if it fails from command line build-add, look to remove ~/dev/ncsa-git/oa4mp/server-test/oa4mp
                System.out.println("***Derby failed. connection=" + derbyConnectionParameters);
                System.out.println("***Derby failed. Clean up  dir=" + derbyConnectionParameters.getRootDirectory() + ", name=" + derbyConnectionParameters.getDatabaseName());
                System.out.println("***Check that the database creation script in server-admin/src/main/resources is up to date.");
            }
            throw t;
        }
    }

    public void testMYSQL() throws Exception {
        testBasic(TestUtils.getMySQLStoreProvider().getClientStore());
    }

    public void testMemStore() throws Exception {
        testBasic(TestUtils.getMemoryStoreProvider().getClientStore());
    }

    public void testPG() throws Exception {
        testBasic(TestUtils.getPgStoreProvider().getClientStore());
    }

    public void testDerby() throws Exception {
        try {
            testBasic(TestUtils.getDerbyStoreProvider().getClientStore());
        }catch(Throwable t){
            SQLStore sqlStore = (SQLStore) TestUtils.getDerbyStoreProvider().getClientStore();
            DerbyConnectionParameters derbyConnectionParameters = ((DerbyConnectionPool)sqlStore.getConnectionPool()).getConnectionParameters();
            System.out.println("Derby failed. Clean up  dir=" + derbyConnectionParameters.getRootDirectory() + ", name" + derbyConnectionParameters.getDatabaseName() );
            System.out.println("Check that the database creation script in server-admin/src/main/resources is up to date.");
            throw t;
        }
    }


    public void testBasic(ClientStore clientStore) throws Exception {
        Client client = (Client) clientStore.create();
        System.out.println("New client ID = " + client.getIdentifier());
        client.setHomeUri("urn:test:/home/uri");
        client.setSecret(getRandomString(256));
        client.setName("Test delegation client");
        client.setEmail("test@email.foo.edu");
        client.setErrorUri("uri:test:/uh/oh/uri");
        client.setProxyLimited(true);
        clientStore.save(client);
        Client client2 = (Client) clientStore.get(client.getIdentifier());
        assert client.getIdentifier().equals(client2.getIdentifier());
        assert client.getHomeUri().equals(client2.getHomeUri());
        assert client.getSecret().equals(client2.getSecret());
        assert client.getName().equals(client2.getName());
        assert client.getEmail().equals(client2.getEmail());
        assert client.getErrorUri().equals(client2.getErrorUri());
        assert client2.isProxyLimited();

        clientStore.remove(client.getIdentifier());
    }
}
