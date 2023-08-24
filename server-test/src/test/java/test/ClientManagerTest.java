package test;

import edu.uiuc.ncsa.myproxy.oa4mp.TestStoreProviderInterface;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientConverter;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientMemoryStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.SAT;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.SATFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.ClientConverter;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.ClientProvider;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.impl.ClientMemoryStore;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;
import net.sf.json.JSONObject;
import org.junit.Test;

/**
 * This tests the client management protocol for OA4MP, not RFC 7591/7592.
 * <p>Created by Jeff Gaynor<br>
 * on 11/14/16 at  9:32 AM
 */
public class ClientManagerTest extends DDServerTests implements SAT {

    public void testAll(TestStoreProviderInterface tp2 ) throws Exception{
        testThing(tp2.getClientStore());
        testApproveSerialization(tp2.getClientStore());
        System.out.println(DD);
        testGetSerialization(tp2);
        System.out.println(DD);
        testNix(tp2);
    }
   @Test
   public void testNix(TestStoreProviderInterface tp2) throws Exception{
       LDAPConfiguration ldap =  ((OA2SE)tp2.getSE()).getLdapConfiguration();
       LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();

       JSONObject json = ldapConfigurationUtil.toJSON(ldap);
       System.out.println("");
       System.out.println("***LDAP configuration for " + ((OA2SE)tp2.getSE()).getClientStore().getClass());
       prettyPrint(json);
       System.out.println("");

    }
    @Test
    public void testApproveSerialization(ClientStore clientStore) throws Exception {
        JSONObject request = new JSONObject();
        JSONObject requestContent = new JSONObject();

        OA2ClientProvider clientProvider = new OA2ClientProvider(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.CLIENT_ID));
        OA2ClientConverter converter = new OA2ClientConverter(clientProvider);
        JSONObject jsonClient = new JSONObject();
        converter.toJSON(getOa2Client(clientStore), jsonClient);
        requestContent.put(KEYS_SUBJECT, jsonClient);
        JSONObject action = new JSONObject();
        action.put("type", "client");
        action.put("method", ACTION_APPROVE);
        requestContent.put(KEYS_ACTION, action);

        JSONObject jsonClient2 = new JSONObject();
        converter.toJSON(getOa2Client(clientStore), jsonClient2);

        requestContent.put(KEYS_TARGET, jsonClient2);

        request.put(KEYS_API, requestContent);
    }

    @Test
      public void testGetSerialization(TestStoreProviderInterface tp2) throws Exception {
          JSONObject request = new JSONObject();
          JSONObject requestContent = new JSONObject();
          DDServerTests.CC cc = setupClients(tp2);
          OA2ClientProvider clientProvider = new OA2ClientProvider(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.CLIENT_ID));

          JSONObject jsonClient = new JSONObject();
          getAdminClientConverter(tp2).toJSON(cc.adminClient, jsonClient);
          requestContent.put(KEYS_SUBJECT, jsonClient);
          JSONObject action = new JSONObject();
          action.put("type", SAT.TYPE_CLIENT);
          action.put("method", ACTION_GET);

          requestContent.put(KEYS_ACTION, action);

          JSONObject jsonClient2 = new JSONObject();
          getClientConverter(tp2).toJSON(cc.client, jsonClient2);

          requestContent.put(KEYS_TARGET, jsonClient2);

          request.put(KEYS_API, requestContent);
        cleanupCC(cc, tp2);
      }
    @Test
    public void testThing(ClientStore clientStore) throws Exception {
        // create a request and use the SATFactory to pull it apart.
        JSONObject request = new JSONObject();
        JSONObject requestContent = new JSONObject();

        OA2ClientProvider clientProvider = new OA2ClientProvider(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.CLIENT_ID));
        OA2ClientConverter converter = new OA2ClientConverter(clientProvider);
        JSONObject jsonClient = new JSONObject();
        converter.toJSON(getOa2Client(clientStore), jsonClient);
        requestContent.put(KEYS_SUBJECT, jsonClient);
        JSONObject action = new JSONObject();
        action.put("type", "client");
        action.put("method", ACTION_APPROVE);
        requestContent.put(KEYS_ACTION, action);

        JSONObject jsonClient2 = new JSONObject();
        converter.toJSON(getOa2Client(clientStore), jsonClient2);

        requestContent.put(KEYS_TARGET, jsonClient2);

        request.put(KEYS_API, requestContent);

        System.out.println(SATFactory.getSubject(request));
        System.out.println(SATFactory.getMethod(request));
        System.out.println(SATFactory.getType(request));
        System.out.println(SATFactory.getTarget(request));
        System.out.println(SATFactory.getContent(request));

    }

      /*
      Generic client test
       */

    @Test
    public void testClient() throws Exception {
        ClientProvider clientProvider = new ClientProvider(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.CLIENT_ID));

        ClientMemoryStore store = new ClientMemoryStore(clientProvider);
        ClientConverter converter = new ClientConverter(clientProvider);
        Client c = getClient(store);
        JSONObject j = new JSONObject();
        converter.toJSON(c, j);
        Client c2 = converter.fromJSON(j);
        assert c2.equals(c);


    }

    @Test
    public void testOA2Client() throws Exception {
        OA2ClientProvider clientProvider = new OA2ClientProvider(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.CLIENT_ID));
        OA2ClientMemoryStore store = new OA2ClientMemoryStore(clientProvider);
        OA2ClientConverter converter = new OA2ClientConverter(clientProvider);

        OA2Client c = getOa2Client(store);
        JSONObject j = new JSONObject();

        converter.toJSON(c, j);
        System.out.println(j);
        Client c2 = converter.fromJSON(j);
        assert c2.equals(c);

    }

    /**
     * This checks that the test-created LDAP configuration can be serialized to and from JSON. If this
     * fails then other tests will fail but the reason might not be obvious.
     * @throws Exception
     */

    @Test
    public void testldapExample() throws Exception {
        LDAPConfiguration ldap = createLDAP();
        LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();

        JSONObject json = ldapConfigurationUtil.toJSON(ldap);
        LDAPConfiguration ldap2 = ldapConfigurationUtil.fromJSON(json);
    }

    protected LDAPConfiguration createLDAP() {
        LDAPConfiguration ldap = new LDAPConfiguration();
        ldap.setServer("foo.bar.edu");
        ldap.setAuthType(LDAPConfigurationUtil.LDAP_AUTH_SIMPLE_KEY);
        ldap.setContextName("ou=foo/cn=bar" + System.currentTimeMillis());

        for (int i = 0; i < 3; i++) {
            LDAPConfigurationUtil.AttributeEntry ae = new LDAPConfigurationUtil.AttributeEntry("source" + i, "target" + i, (i % 2 == 0), false);
            ldap.getSearchAttributes().put(ae.sourceName, ae);

        }
        SSLConfiguration ssl = new SSLConfiguration();
        ssl.setKeystorePassword("changeme");
        ssl.setKeystoreType("JKS");
        ssl.setKeystore(DebugUtil.getConfigPath()+"/cacerts2");
        ldap.setSslConfiguration(ssl);
        System.out.println(DD);
        System.out.println("LDAP from config serializer:");
        return ldap;
    }



}
