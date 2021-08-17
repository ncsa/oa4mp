package edu.uiuc.ncsa.myproxy.oa4mp;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientApprovalProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore.DSFSClientApprovalStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.ClientApproverConverter;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.FilePermissionsException;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.server.storage.impl.FSClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.util.TestBase;

import java.io.File;
import java.util.Date;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/26/17 at  2:58 PM
 */

public class NewCAStoreTest extends TestBase {
    public void testFS() throws Exception {
        testApprovalStore(TestUtils.getFsStoreProvider().getClientStore(), TestUtils.getFsStoreProvider().getClientApprovalStore());
        testApprovalCycle(TestUtils.getFsStoreProvider().getClientStore(), TestUtils.getFsStoreProvider().getClientApprovalStore());
    }

    public void testMYSQL() throws Exception {
        testApprovalStore(TestUtils.getMySQLStoreProvider().getClientStore(), TestUtils.getMySQLStoreProvider().getClientApprovalStore());
        testApprovalCycle(TestUtils.getMySQLStoreProvider().getClientStore(), TestUtils.getMySQLStoreProvider().getClientApprovalStore());
    }

    public void testMemStore() throws Exception {
        testApprovalStore(TestUtils.getMemoryStoreProvider().getClientStore(), TestUtils.getMemoryStoreProvider().getClientApprovalStore());
        testApprovalCycle(TestUtils.getMemoryStoreProvider().getClientStore(), TestUtils.getMemoryStoreProvider().getClientApprovalStore());
    }

    public void testPG() throws Exception {
        testApprovalStore(TestUtils.getPgStoreProvider().getClientStore(), TestUtils.getPgStoreProvider().getClientApprovalStore());
        testApprovalCycle(TestUtils.getPgStoreProvider().getClientStore(), TestUtils.getPgStoreProvider().getClientApprovalStore());
    }

    public void testDerby() throws Exception {
        testApprovalStore(TestUtils.getDerbyStoreProvider().getClientStore(), TestUtils.getPgStoreProvider().getClientApprovalStore());
        testApprovalCycle(TestUtils.getDerbyStoreProvider().getClientStore(), TestUtils.getPgStoreProvider().getClientApprovalStore());
    }


    public void testApprovalStore(ClientStore clientStore,
                                  ClientApprovalStore caStore) throws Exception {
        // put one in, get it back, make sure it matches.
        Client client = (Client) clientStore.create();
        client.setHomeUri("urn:test:/home/uri/" + getRandomString(32));
        client.setSecret(getRandomString(256));
        client.setName("Test client" + getRandomString(32));
        client.setEmail(getRandomString(32) + "@email.foo.edu");
        client.setErrorUri("uri:test:/uh/oh/uri/" + getRandomString(32));

        clientStore.save(client);

        ClientApproval ca = (ClientApproval) caStore.create();
        ca.setApprover("test-approver");
        ca.setApproved(true);
        ca.setApprovalTimestamp(new Date());
        ca.setIdentifier(client.getIdentifier());
        caStore.save(ca);

        ClientApproval ca1 = (ClientApproval) caStore.get(ca.getIdentifier());
        assert ca.equals(ca1);
        caStore.remove(ca.getIdentifier());
        clientStore.remove(client);
    }

    public void testApprovalCycle(ClientStore clientStore,
                                  ClientApprovalStore caStore) throws Exception {
        // approval of something not in the store means it is not approved.

        assert !caStore.isApproved(BasicIdentifier.newID("foo:bar:baz://" + getRandomString(32)));

        Client client = (Client) clientStore.create();
        Identifier identifier = client.getIdentifier();

        client.setHomeUri("urn:test:/home/uri/" + getRandomString(32));
        client.setSecret(getRandomString(256));
        client.setName("Test client" + getRandomString(32));
        client.setEmail(getRandomString(32) + "@email.foo.edu");
        client.setErrorUri("uri:test:/uh/oh/uri/" + getRandomString(32));
        clientStore.save(client);

        ClientApproval ca = (ClientApproval) caStore.create();
        ca.setApprover("test-approver");
        ca.setApproved(false);
        ca.setApprovalTimestamp(new Date());
        ca.setIdentifier(identifier);
        caStore.save(ca);

        assert !((ClientApproval) caStore.get(client.getIdentifier())).isApproved();

        assert !caStore.isApproved(identifier);
        ca.setApproved(true);
        caStore.save(ca);

        // Regression test to be sure that identifiers are never changed.
        assert identifier.equals(ca.getIdentifier());
        assert identifier.equals(client.getIdentifier());
        assert ((ClientApproval) caStore.get(client.getIdentifier())).isApproved();
        assert caStore.isApproved(identifier);

        caStore.remove(client.getIdentifier());
        clientStore.remove(client.getIdentifier());

    }

    public void testPermissions() throws Exception {
          File storeDirectory = File.createTempFile("fs-store", "-tmp");
          File indexDirectory = File.createTempFile("fs-index", "-tmp");

          storeDirectory.setWritable(false);
          indexDirectory.setWritable(false);

          assert !storeDirectory.canWrite();
          FSClientApprovalStore x = null;
          final ClientApprovalProvider caProvider = new ClientApprovalProvider();
          try {
              // Make sure that if someone creates a bad one, it blows up in the constructor.
               x = new FSClientApprovalStore(null, null, null, null, true) {
                   @Override
                   public List<Identifier> statusSearch(String status) {
                       return null;
                   }

                   @Override
                         public Object put(Object key, Object value) {
                             return null;
                         }
                     };
              assert false : "Could make a new object without being properly configured";

          } catch (MyConfigurationException xx) {
              assert true;
          }
          x = new DSFSClientApprovalStore(storeDirectory, indexDirectory,  caProvider,  new ClientApproverConverter(caProvider), true);
          try {
              x.create(); // should bomb here.
              assert false;
          } catch (FilePermissionsException xx) {
              assert true;
          }
          // so make a new entry and then have retrieving it fail.

          storeDirectory.setWritable(true);
          indexDirectory.setWritable(true);
          ClientApproval ca  = (ClientApproval) x.create();

          // fail for store directory un readable
          storeDirectory.setReadable(false);
          try{
              x.get(ca.getIdentifier());
              assert false;
          }catch(FilePermissionsException xx){
              assert true;
          }

      }

}
