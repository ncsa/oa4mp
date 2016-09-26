import edu.uiuc.ncsa.myproxy.client.*;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.*;
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
        AssetStoreTest.class,
        ClientConfigTest.class
})

public class ClientTestSuite extends TestSuite {
    @BeforeClass
    public static void setUp() throws Exception {
        String schema = "oauth";
        String databaseName = "ncsa";
        String tableName = "assets";
        AssetProvider ap = new AssetProvider();
        AssetSerializationKeys keys = new AssetSerializationKeys();
        AssetStoreTable table = new AssetStoreTable(new AssetSerializationKeys(), schema, "", tableName);
        AssetConverter ac = new AssetConverter(keys, ap);
        ClientTestStoreUtil.setMemoryStore(new MemoryAssetStore(ap));

        ClientTestStoreUtil.setFileStore(new FSAssetStore(ClientTestStoreUtil.createTempDir(), ap, ac));
        ClientTestStoreUtil.setPostgresStore(ClientTestStoreUtil.setupPGStore(databaseName, schema, ap, ac, table));
        ClientTestStoreUtil.setMysqlStore(ClientTestStoreUtil.setupMySQLStore(databaseName, schema, ap, ac, table));

    }


}
