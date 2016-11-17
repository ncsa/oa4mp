package edu.uiuc.ncsa.co;

import edu.uiuc.ncsa.co.loader.LDAPConfiguration2;
import edu.uiuc.ncsa.co.loader.LDAPConfigurationUtil2;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider;
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
import net.sf.json.JSONObject;
import net.sf.json.util.JSONUtils;

import java.util.LinkedList;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/14/16 at  9:32 AM
 */
public class CMTester {
    public static void main(String[] args){
          clientConverter();
        oa2clientConverter();
        ldapExample();
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
    protected static void clientConverter(){
        ClientProvider clientProvider = new ClientProvider(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.CLIENT_ID));

        ClientMemoryStore store = new ClientMemoryStore(clientProvider);
        ClientConverter converter = new ClientConverter(clientProvider);
        Client c = (Client) store.create();
        c.setSecret("idufh84057thsdfghwre");
        c.setProxyLimited(true);
        c.setHomeUri("https://baz.foo.edu/home");
        c.setErrorUri("https://baz.foo.edu/home/error");
        c.setProxyLimited(false);
        c.setEmail("bob@foo.bar");
        c.setName("Test client 42");
        JSONObject j = new JSONObject();
        converter.toJSON(c, j);
        System.out.println(j);
        Client c2 = converter.fromJSON(j);
        System.out.println("equal?" + c2.equals(c));


    }

    protected static void oa2clientConverter(){
        OA2ClientProvider clientProvider = new OA2ClientProvider(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.CLIENT_ID));

        ClientMemoryStore store = new ClientMemoryStore(clientProvider);
        OA2ClientConverter converter = new OA2ClientConverter(clientProvider);
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
        JSONObject j = new JSONObject();
        converter.toJSON(c, j);
        System.out.println(j);
        Client c2 = converter.fromJSON(j);
        System.out.println("equal?" + c2.equals(c));

    }

    public static void ldapExample(){
        LDAPConfiguration2 ldap = new LDAPConfiguration2();
        ldap.setServer("foo.bar.edu");
        ldap.setAuthType(LDAPConfigurationUtil2.LDAP_AUTH_SIMPLE_KEY);
        ldap.setContextName("ou=foo/cn=bar");

        for(int i = 0; i < 3; i++){
            LDAPConfigurationUtil.AttributeEntry ae = new LDAPConfigurationUtil.AttributeEntry("source" + i,"target" + i, (i%2 == 0));
            ldap.getSearchAttributes().put(ae.sourceName, ae);

        }
        SSLConfiguration ssl = new SSLConfiguration();
        ssl.setKeystorePassword("changeme");
        ssl.setKeystoreType("JKS");
        ssl.setKeystore("/home/ncsa/dev/csd/config/cacerts2");
        ldap.setSslConfiguration(ssl);
        JSONObject json = LDAPConfigurationUtil2.toJSON(ldap);
        prettyPrint(json);
        LDAPConfiguration ldap2 = LDAPConfigurationUtil2.fromJSON(json);
        System.out.println(ldap2.equals(ldap));
    }
}
