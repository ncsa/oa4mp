package edu.uiuc.ncsa.myproxy.oa4mp.file;

import edu.uiuc.ncsa.myproxy.oa4mp.CAStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.TestStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientApprovalProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore.DSFSClientApprovalStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.ClientApproverConverter;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.exceptions.FilePermissionsException;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.impl.FSClientApprovalStore;
import edu.uiuc.ncsa.security.storage.FileStore;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/4/12 at  2:58 PM
 */
public class FSCAStoreTest extends CAStoreTest {
    @Override
    protected Class getStoreClass() {
        return FileStore.class;
    }

    @Override
    public TestStoreProvider getTSProvider() {
        return TestUtils.getFsStoreProvider();
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
             x = new FSClientApprovalStore(null, null, null, null) {
                       @Override
                       public Object put(Object key, Object value) {
                           return null;
                       }
                   };
            assert false : "Could make a new object without being properly configured";

        } catch (MyConfigurationException xx) {
            assert true;
        }
        x = new DSFSClientApprovalStore(storeDirectory, indexDirectory,  caProvider,  new ClientApproverConverter(caProvider));
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
