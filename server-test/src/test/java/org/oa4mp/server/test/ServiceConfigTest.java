package org.oa4mp.server.test;

import edu.uiuc.ncsa.security.core.cf.CFBundle;
import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.core.configuration.ConfigTest;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.HierarchicalConfigProvider;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.storage.sql.derby.DerbyConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.mariadb.MariaDBConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.mysql.MySQLConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.postgres.PGConnectionPoolProvider;
import org.junit.Test;
import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.common.storage.clients.ClientConverter;
import org.oa4mp.delegation.common.storage.clients.ClientProvider;
import org.oa4mp.delegation.server.storage.ClientApproval;
import org.oa4mp.delegation.server.storage.ClientApprovalStore;
import org.oa4mp.delegation.server.storage.ClientStore;
import org.oa4mp.server.api.ClientApprovalProvider;
import org.oa4mp.server.api.OA4MPConfigTags;
import org.oa4mp.server.api.admin.transactions.OA4MPIdentifierProvider;
import org.oa4mp.server.api.storage.MultiDSClientApprovalStoreProvider;
import org.oa4mp.server.api.storage.MultiDSClientStoreProvider;
import org.oa4mp.server.api.storage.filestore.DSFSClientApprovalStoreProvider;
import org.oa4mp.server.api.storage.filestore.DSFSClientStoreProvider;
import org.oa4mp.server.api.storage.sql.SQLClientApprovalStore;
import org.oa4mp.server.api.storage.sql.SQLClientStore;
import org.oa4mp.server.api.storage.sql.provider.DSSQLClientApprovalStoreProvider;
import org.oa4mp.server.api.util.ClientApproverConverter;
import org.oa4mp.server.loader.oauth2.loader.OA2CFConfigurationLoader;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2ClientMemoryStore;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2ClientSQLStoreProvider;

import static org.oa4mp.server.api.OA4MPConfigTags.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/5/11 at  10:16 AM
 */
public class ServiceConfigTest extends ConfigTest {

    @Override
    protected CFBundle getConfiguration() {
        // File at oa4mp/server-api/src/main/resources/server-test.xml
        //return getConfiguration(DebugUtil.getDevPath() + "/oa4mp/server-api/src/main/resources/server-test.xml");
        return getConfiguration("server-test.xml");
    }

    @Override
    protected String getConfigurationType() {
        return "service";
    }

    /**
     * A Dummy provider to let us test the machinery of the base HierarchicalConfigProvider,
     * indep. of what is provided. (If the machinery does not work, can't ever get a
     * provider to actual provide something, so this is more important as a regression test.)
     */
    protected static class TestProvider extends HierarchicalConfigProvider<Object> {
        @Override
        public Object componentFound(CfgEvent configurationEvent) {
            throw new NotImplementedException();
        }

        public TestProvider(CFNode config) {
            super(config);
        }


        @Override
        public Object get() {
            throw new NotImplementedException("woops...");
        }

        @Override
        protected boolean checkEvent(CfgEvent cfgEvent) {
            return true;
        }
    }


    /**
     * Just reads in the configuration and calls "get" on the provider. This should work if the
     * configuration file is read.
     *
     * @throws Exception
     */
    @Test
    public void testClientStoreProvider() throws Exception {
       CFNode cn = getConfig("mixed config");
       // CFNode cn = getConfig("postgresql config");

        ClientProvider clientProvider = new ClientProvider(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.CLIENT_ID));
        MultiDSClientStoreProvider csp = new OA2CFConfigurationLoader.OA2MultiDSClientStoreProvider(cn, false, new MyLoggingFacade("test"), null, null, clientProvider);
        ClientConverter converter = new ClientConverter(clientProvider);
        csp.addListener(new DSFSClientStoreProvider(cn, converter, clientProvider));
        csp.addListener(new OA2ClientSQLStoreProvider(new MySQLConnectionPoolProvider("oauth", "oauth"),
                OA4MPConfigTags.MYSQL_STORE,
                converter, clientProvider));
        csp.addListener(new OA2ClientSQLStoreProvider(new MariaDBConnectionPoolProvider("oauth", "oauth"),
                OA4MPConfigTags.MARIADB_STORE,
                converter, clientProvider));
        csp.addListener(new OA2ClientSQLStoreProvider(new PGConnectionPoolProvider("oauth", "oauth"),
                OA4MPConfigTags.POSTGRESQL_STORE,
                converter, clientProvider));
        csp.addListener(new OA2ClientSQLStoreProvider(new DerbyConnectionPoolProvider("oauth", "oauth"),
                OA4MPConfigTags.DERBY_STORE,
                converter, clientProvider));
        csp.addListener(new TypedProvider<ClientStore>(cn, OA4MPConfigTags.MEMORY_STORE, OA4MPConfigTags.CLIENTS_STORE) {
            @Override
            public Object componentFound(CfgEvent configurationEvent) {
                if (checkEvent(configurationEvent)) {
                    return get();
                }
                return null;
            }

            @Override
            public ClientStore get() {
                return new OA2ClientMemoryStore(clientProvider);
            }
        });
        ClientStore<Client> cs = (ClientStore<Client>) csp.get();
        assert cs instanceof SQLClientStore;
    }

    /*
         OA2ClientConverter converter = new OA2ClientConverter(getClientProvider());
                csp = new OA2MultiDSClientStoreProvider(cn, isDefaultStoreDisabled(), getMyLogger(), null, null, getClientProvider());
                csp.addListener(new DSFSClientStoreProvider(cn, converter, getClientProvider()));
                csp.addListener(new OA2ClientSQLStoreProvider(getMySQLConnectionPoolProvider(),
                        OA4MPConfigTags.MYSQL_STORE,
                        converter, getClientProvider()));
                csp.addListener(new OA2ClientSQLStoreProvider(getMariaDBConnectionPoolProvider(),
                        OA4MPConfigTags.MARIADB_STORE,
                        converter, getClientProvider()));
                csp.addListener(new OA2ClientSQLStoreProvider(getPgConnectionPoolProvider(),
                        OA4MPConfigTags.POSTGRESQL_STORE,
                        converter, getClientProvider()));
                csp.addListener(new OA2ClientSQLStoreProvider(getDerbyConnectionPoolProvider(),
                        OA4MPConfigTags.DERBY_STORE,
                        converter, getClientProvider()));
                csp.addListener(new TypedProvider<ClientStore>(cn, OA4MPConfigTags.MEMORY_STORE, OA4MPConfigTags.CLIENTS_STORE) {

     */
    public void testClientApprovalStoreProvider() throws Exception {
        CFNode cn = getConfig("postgresql config");
        MultiDSClientApprovalStoreProvider dap = new MultiDSClientApprovalStoreProvider(cn, true, new MyLoggingFacade("test"), null, null);
        ClientApproverConverter cp = new ClientApproverConverter(new ClientApprovalProvider());

        dap.addListener(new DSFSClientApprovalStoreProvider(cn, cp));
        dap.addListener(new DSSQLClientApprovalStoreProvider(cn, new MySQLConnectionPoolProvider("oauth", "oauth"), MYSQL_STORE, cp));
        dap.addListener(new DSSQLClientApprovalStoreProvider(cn, new PGConnectionPoolProvider("oauth", "oauth"), POSTGRESQL_STORE, cp));
        dap.addListener(new DSSQLClientApprovalStoreProvider(cn, new DerbyConnectionPoolProvider("oa4mp", "oauth2"), DERBY_STORE, cp));
        ClientApprovalStore<ClientApproval> as = (ClientApprovalStore<ClientApproval>) dap.get();
        assert as instanceof SQLClientApprovalStore;


    }


    @Test
    public void testServerConfig() throws Exception {
        // tests getting the configuration and the new providers. A sample test file is in src/main/resources.
        CFNode config = getConfig("mixed config");
        TestProvider service = new TestProvider(getConfig("mixed config"));


        TestProvider fsp = new TestProvider(config.getFirstNode(FILE_STORE));

        TestProvider mail = new TestProvider(config.getFirstNode(MAIL));
        assert mail.getBooleanAttribute("enabled");
        assert fsp.isA(FILE_STORE) : "NOT a filestore!";
        assert !fsp.isA(MYSQL_STORE) : "Is a mysql store and should not be";
        assert !fsp.hasA(CLIENT_APPROVAL_STORE) : "Should NOT provide client approvals and it does";
        assert fsp.hasA(TRANSACTIONS_STORE) : "Should provide transactions";
    }

    @Test
    public void testConfig() throws Exception {
        print(getConfiguration());
/*
        List<String> names = bundle.getAllConfigNames();
        say("echoing configuration to console:");
        ConfigurationNode root = c.getRootNode();
        say("name of root = " + root.getName());
        say("child count = " + root.getChildren().size());

        while (iterator.hasNext()) {
            String key = iterator.next().toString();
            say("(k, v)=(" + key + ", " + c.getString(key) + ")");
        }

        SubnodeConfiguration mailC = c.configurationAt("service.mail");
        say("mail configured? "+ mailC.getString("[@enabled]"));
*/
    }


}
