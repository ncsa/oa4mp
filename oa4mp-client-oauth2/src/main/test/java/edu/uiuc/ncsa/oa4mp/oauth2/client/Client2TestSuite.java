package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.client.*;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.FSAssetStore;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.MemoryAssetStore;
import junit.framework.TestSuite;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/8/14 at  12:54 PM
 */
@RunWith(Suite.class)

@Suite.SuiteClasses({
        PKCS10_CSR_Test.class,
        ClientParameterTest.class,
        Client2AssetStoreTest.class,
        ClientConfigTest.class
})

public class Client2TestSuite extends TestSuite {
    @BeforeClass
    public static void setUp() throws Exception {
        String schema = "oauth2";
        String databaseName = "ncsa";
        String tableName = "assets";
        OA2AssetProvider assetProvider = new OA2AssetProvider();
        OA2AssetConverter converter = new OA2AssetConverter(new OA2AssetSerializationKeys(), assetProvider);
        OA2AssetSerializationKeys keys = new OA2AssetSerializationKeys();
        OA2AssetStoreTable table = new OA2AssetStoreTable(keys,schema,"",tableName);
        ClientTestStoreUtil.setMemoryStore(new MemoryAssetStore(assetProvider));
        ClientTestStoreUtil.setFileStore(new FSAssetStore(ClientTestStoreUtil.createTempDir(), assetProvider, converter));
        ClientTestStoreUtil.setPostgresStore(ClientTestStoreUtil.setupPGStore(databaseName,schema,assetProvider,converter,table));
        ClientTestStoreUtil.setMysqlStore(ClientTestStoreUtil.setupMySQLStore(databaseName,schema,assetProvider,converter,table));
    }

}
