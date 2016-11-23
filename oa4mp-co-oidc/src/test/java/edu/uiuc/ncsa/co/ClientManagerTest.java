package edu.uiuc.ncsa.co;

import edu.uiuc.ncsa.co.ldap.LDAPEntry;
import edu.uiuc.ncsa.co.ldap.LDAPStore;
import edu.uiuc.ncsa.co.loader.LDAPConfiguration2;
import edu.uiuc.ncsa.co.loader.LDAPConfigurationUtil2;
import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.SAT;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.SATFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.server.storage.impl.ClientMemoryStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.ClientProvider;
import edu.uiuc.ncsa.security.delegation.storage.impl.ClientConverter;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ClientConverter;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ClientProvider;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;
import edu.uiuc.ncsa.security.oauth_2_0.server.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;
import junit.framework.TestCase;
import net.sf.json.JSONObject;
import net.sf.json.util.JSONUtils;
import org.junit.Test;

import java.util.LinkedList;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/14/16 at  9:32 AM
 */
public class ClientManagerTest extends TestCase implements SAT {
    public void testSerialization() throws Exception {
    }

    public void testMemoryStore() throws Exception {
        CMTestStoreProvider tp2 = (CMTestStoreProvider) TestUtils.getMemoryStoreProvider();
        testThing(tp2.getClientStore());
        testSerialization(tp2.getClientStore());
        testLDAPStore(tp2.getLDAPStore(), tp2.getClientStore());
        testLDAPStore2(tp2.getLDAPStore(), tp2.getClientStore());
    }

    public void testFilestore() throws Exception {
        CMTestStoreProvider tp2 = (CMTestStoreProvider) TestUtils.getFsStoreProvider();
        testThing(tp2.getClientStore());
        testSerialization(tp2.getClientStore());
        testLDAPStore(tp2.getLDAPStore(), tp2.getClientStore());
        testLDAPStore2(tp2.getLDAPStore(), tp2.getClientStore());
    }

    public void testMysql() throws Exception {
        CMTestStoreProvider tp2 = (CMTestStoreProvider) TestUtils.getMySQLStoreProvider();
        testThing(tp2.getClientStore());
        testSerialization(tp2.getClientStore());
        testLDAPStore(tp2.getLDAPStore(), tp2.getClientStore());
        testLDAPStore2(tp2.getLDAPStore(), tp2.getClientStore());
    }

    public void testPostgres() throws Exception {
        CMTestStoreProvider tp2 = (CMTestStoreProvider) TestUtils.getPgStoreProvider();
        testThing(tp2.getClientStore());
        testSerialization(tp2.getClientStore());
        testLDAPStore(tp2.getLDAPStore(), tp2.getClientStore());
        testLDAPStore2(tp2.getLDAPStore(), tp2.getClientStore());
    }

    @Test
    public void testSerialization(ClientStore clientStore) throws Exception {
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
        prettyPrint(request);
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

        prettyPrint(request);
    }


    public static final String DD = "----------------------------------------------------------------------------";

    public static void x() {
        System.out.println(DD);
    }

    private static void prettyPrint(JSONObject api) {
        String out = JSONUtils.valueToString(api, 1, 0);
        System.out.println(out);
        x();
    }

    protected Client getClient(ClientStore store) {
        Client c = (Client) store.create();
        c.setSecret("idufh84057thsdfghwre");
        c.setProxyLimited(true);
        c.setHomeUri("https://baz.foo.edu/home");
        c.setErrorUri("https://baz.foo.edu/home/error");
        c.setProxyLimited(false);
        c.setEmail("bob@foo.bar");
        c.setName("Test client 42");
        return c;
    }

    @Test
    public void testClient() throws Exception {
        ClientProvider clientProvider = new ClientProvider(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.CLIENT_ID));

        ClientMemoryStore store = new ClientMemoryStore(clientProvider);
        ClientConverter converter = new ClientConverter(clientProvider);
        Client c = getClient(store);
        JSONObject j = new JSONObject();
        converter.toJSON(c, j);
        prettyPrint(j);
        Client c2 = converter.fromJSON(j);
        assert c2.equals(c);


    }

    @Test
    public void testOA2Client() throws Exception {
        OA2ClientProvider clientProvider = new OA2ClientProvider(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.CLIENT_ID));
        ClientMemoryStore store = new ClientMemoryStore(clientProvider);
        OA2ClientConverter converter = new OA2ClientConverter(clientProvider);

        OA2Client c = getOa2Client(store);
        JSONObject j = new JSONObject();

        converter.toJSON(c, j);
        System.out.println(j);
        Client c2 = converter.fromJSON(j);
        assert c2.equals(c);

    }

    private static OA2Client getOa2Client(ClientStore store) {
        OA2Client c = (OA2Client) store.create();
        c.setSecret("idufh84057thsdfghwre");
        c.setProxyLimited(true);
        c.setHomeUri("https://baz.foo.edu/home");
        c.setErrorUri("https://baz.foo.edu/home/error");
        c.setProxyLimited(false);
        c.setEmail("bob@foo.bar");
        c.setName("Test client 42");
        c.setRtLifetime(456767875477L);

        LinkedList<String> callbacks = new LinkedList<>();
        callbacks.add("https:/baz.foo.edu/client2/ready1");
        callbacks.add("https:/baz.foo.edu/client2/ready2");
        c.setCallbackURIs(callbacks);
        LDAPConfiguration ldapConfiguration = new LDAPConfiguration();
        ldapConfiguration.setServer("foo.bar.edu");
        LinkedList<LDAPConfiguration> ldaps = new LinkedList<>();
        ldaps.add(ldapConfiguration);
        c.setLdaps(ldaps);
        LinkedList<String> scopes = new LinkedList<>();
        scopes.add(OA2Scopes.SCOPE_OPENID);
        scopes.add(OA2Scopes.SCOPE_EMAIL);
        scopes.add(OA2Scopes.SCOPE_PROFILE);
        scopes.add(OA2Scopes.SCOPE_CILOGON_INFO);
        c.setScopes(scopes);
        return c;
    }

    @Test
    public void testldapExample() throws Exception {
        LDAPConfiguration2 ldap = createLDAP();
        JSONObject json = LDAPConfigurationUtil2.toJSON(ldap);
        prettyPrint(json);
        LDAPConfiguration ldap2 = LDAPConfigurationUtil2.fromJSON(json);
    }

    protected LDAPConfiguration2 createLDAP() {
        LDAPConfiguration2 ldap = new LDAPConfiguration2();
        ldap.setServer("foo.bar.edu");
        ldap.setAuthType(LDAPConfigurationUtil2.LDAP_AUTH_SIMPLE_KEY);
        ldap.setContextName("ou=foo/cn=bar" + System.currentTimeMillis());

        for (int i = 0; i < 3; i++) {
            LDAPConfigurationUtil.AttributeEntry ae = new LDAPConfigurationUtil.AttributeEntry("source" + i, "target" + i, (i % 2 == 0));
            ldap.getSearchAttributes().put(ae.sourceName, ae);

        }
        SSLConfiguration ssl = new SSLConfiguration();
        ssl.setKeystorePassword("changeme");
        ssl.setKeystoreType("JKS");
        ssl.setKeystore("/home/ncsa/dev/csd/config/cacerts2");
        ldap.setSslConfiguration(ssl);
        return ldap;
    }

    public void testLDAPStore(LDAPStore<LDAPEntry> ldapStore, ClientStore clientStore) throws Exception {
        OA2Client oa2Client = (OA2Client) clientStore.create();
        LDAPConfiguration2 ldap = createLDAP();
        LDAPEntry ldapEntry = ldapStore.create();
        ldapEntry.setClientID(oa2Client.getIdentifier());
        ldapEntry.setConfiguration(ldap);
        ldapStore.save(ldapEntry);
        LDAPEntry ldapEntry1 = ldapStore.get(ldapEntry.getIdentifier());
        assert ldapEntry.equals(ldapEntry1);

    }

    /**
     * Retrieve a configuration by its client id.
     * @param ldapStore
     * @param clientStore
     * @throws Exception
     */
    public void testLDAPStore2(LDAPStore<LDAPEntry> ldapStore, ClientStore clientStore) throws Exception {
        OA2Client oa2Client = (OA2Client) clientStore.create();
        LDAPConfiguration2 ldap = createLDAP();
        LDAPEntry ldapEntry = ldapStore.create();
        ldapEntry.setClientID(oa2Client.getIdentifier());
        ldapEntry.setConfiguration(ldap);
        ldapStore.save(ldapEntry);
        LDAPEntry ldapEntry1 = ldapStore.getByClientID(ldapEntry.getClientID());
        assert ldapEntry.equals(ldapEntry1);

    }

}
