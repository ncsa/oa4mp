package edu.uiuc.ncsa.myproxy.oa4mp;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientApprovalProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.MultiDSClientApprovalStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.MultiDSClientStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore.DSFSClientApprovalStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore.DSFSClientStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.provider.DSClientSQLStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.provider.DSSQLClientApprovalStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.ClientApproverConverter;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.core.configuration.ConfigTest;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.HierarchicalConfigProvider;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.ClientProvider;
import edu.uiuc.ncsa.security.delegation.storage.impl.ClientConverter;
import edu.uiuc.ncsa.security.storage.sql.mysql.MySQLConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.postgres.PGConnectionPoolProvider;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.SubnodeConfiguration;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.configuration.tree.ConfigurationNode;
import org.junit.Test;

import java.util.Iterator;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/5/11 at  10:16 AM
 */
public class ServiceConfigTest extends ConfigTest {
    @Override
    protected XMLConfiguration getConfiguration() throws ConfigurationException {
        return getConfiguration("/server-test.xml");
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

        public TestProvider(ConfigurationNode config) {
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
     * @throws Exception
     */
    @Test
    public void testClientStoreProvider() throws Exception{
        ConfigurationNode cn = getConfig("mixed config");
        ClientProvider clientProvider = new ClientProvider(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.CLIENT_ID));
        MultiDSClientStoreProvider csp = new MultiDSClientStoreProvider(cn, true, new MyLoggingFacade("test"), null, null,clientProvider);
         ClientConverter converter = new ClientConverter(clientProvider);
        csp.addListener(new DSFSClientStoreProvider(cn, converter,clientProvider));
        csp.addListener(new DSClientSQLStoreProvider(cn, new MySQLConnectionPoolProvider("oauth", "oauth"), MYSQL_STORE, converter,clientProvider));
        csp.addListener(new DSClientSQLStoreProvider(cn, new PGConnectionPoolProvider("oauth", "oauth"), POSTGRESQL_STORE, converter, clientProvider));
        ClientStore<Client> cs = (ClientStore<Client>) csp.get();
    }

    public void testClientApprovalStoreProvider() throws Exception{
        ConfigurationNode cn =getConfig("postgresql config");
        MultiDSClientApprovalStoreProvider dap = new MultiDSClientApprovalStoreProvider(cn, true, new MyLoggingFacade("test"),  null, null);
        ClientApproverConverter cp = new ClientApproverConverter(new ClientApprovalProvider());

        dap.addListener(new DSFSClientApprovalStoreProvider(cn, cp));
        dap.addListener(new DSSQLClientApprovalStoreProvider(cn, new MySQLConnectionPoolProvider("oauth", "oauth"), MYSQL_STORE, cp));
        dap.addListener(new DSSQLClientApprovalStoreProvider(cn, new PGConnectionPoolProvider("oauth", "oauth"), POSTGRESQL_STORE, cp));
        ClientApprovalStore<ClientApproval> as = (ClientApprovalStore<ClientApproval>) dap.get();
    }


    @Test
    public void testServerConfig() throws Exception {
        // tests getting the configuration and the new providers. A sample test file is in src/main/resources.


        ConfigurationNode zzz = getConfiguration().getRootNode();
        TestProvider service = new TestProvider(getConfig("mixed config"));


        TestProvider fsp = new TestProvider(service.getConfigurationAt(FILE_STORE));

        TestProvider mail = new TestProvider(service.getConfigurationAt(MAIL));
        assert mail.getBooleanAttribute("enabled");
        assert fsp.isA(FILE_STORE) : "NOT a filestore!";
        assert !fsp.isA(MYSQL_STORE) : "Is a mysql store and should not be";
        assert !fsp.hasA(CLIENT_APPROVAL_STORE) : "Should NOT provide client approvals and it does";
        assert fsp.hasA(TRANSACTIONS_STORE) : "Should provide transactions";
    }

    @Test
    public void testConfig() throws Exception {
        XMLConfiguration c = getConfiguration();
        Iterator iterator = c.getKeys();
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
    }




}
