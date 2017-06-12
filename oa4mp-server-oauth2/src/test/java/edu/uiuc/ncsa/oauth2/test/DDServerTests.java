package edu.uiuc.ncsa.oauth2.test;

import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientConverter;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStoreProviders;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionList;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.impl.BaseClientConverter;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import edu.uiuc.ncsa.security.oauth_2_0.server.LDAPConfiguration;
import junit.framework.TestCase;
import net.sf.json.JSONObject;
import net.sf.json.util.JSONUtils;
import org.apache.commons.codec.binary.Base64;

import java.security.SecureRandom;
import java.util.LinkedList;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/1/16 at  1:06 PM
 */
public abstract class DDServerTests extends TestCase {
    public abstract void testAll(CMTestStoreProvider tp2) throws Exception;

    public void testMemoryStore() throws Exception {
        testAll((CMTestStoreProvider) TestUtils.getMemoryStoreProvider());
    }

    public void testFilestore() throws Exception {
        testAll((CMTestStoreProvider) TestUtils.getFsStoreProvider());
    }

    public void testMysql() throws Exception {
        testAll((CMTestStoreProvider) TestUtils.getMySQLStoreProvider());
    }

    public void testPostgres() throws Exception {
        testAll((CMTestStoreProvider) TestUtils.getPgStoreProvider());
    }

    public static class CC {
        public AdminClient adminClient;
        public OA2Client client;
    }

    SecureRandom secureRandom = new SecureRandom();

    protected String getRandom() {
        return getRandom(16);
    }

    protected String getRandom(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return Base64.encodeBase64URLSafeString(bytes);
    }

    protected CC setupClients(CMTestStoreProvider tp2) throws Exception {
        AdminClient adminClient = getAdminClient(tp2.getAdminClientStore());
        ClientApproval clientApproval = tp2.getClientApprovalStore().create();
        clientApproval.setIdentifier(adminClient.getIdentifier());
        clientApproval.setApproved(true);
        clientApproval.setApprover("junit");
        tp2.getClientApprovalStore().save(clientApproval );

        OA2Client client = getOa2Client(tp2.getClientStore());

        PermissionList permissions = tp2.getPermissionStore().get(adminClient.getIdentifier(), client.getIdentifier());
        if (permissions.isEmpty()) {
            Permission p = tp2.getPermissionStore().create();
            p.setAdminID(adminClient.getIdentifier());
            p.setClientID(client.getIdentifier());
            p.setRead(true);
            p.setWrite(true);
            p.setDelete(true);
            p.setApprove(true);
            p.setCreate(true);
            tp2.getPermissionStore().save(p);
        }
        CC cc = new CC();
        cc.adminClient = adminClient;
        cc.client = client;
        return cc;
    }

    protected AdminClientConverter getAdminClientConverter(CMTestStoreProvider tp2) throws Exception {
        BaseClientConverter bcc = tp2.getAdminClientStore().getACConverter();
        if (bcc instanceof AdminClientConverter) {
            return (AdminClientConverter) bcc;
        }

        return AdminClientStoreProviders.getAdminClientConverter();
    }
    protected OA2ClientConverter getClientConverter(CMTestStoreProvider tp2) throws Exception {
        BaseClientConverter bcc = tp2.getClientStore().getACConverter();
        if (bcc instanceof OA2ClientConverter) {
            return (OA2ClientConverter) bcc;
        }
        // In the weird chance something does not have one, the default is provided.
        OA2ClientProvider clientProvider = new OA2ClientProvider(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.CLIENT_ID));
        OA2ClientConverter converter = new OA2ClientConverter(clientProvider);

        return converter;
    }

    protected OA2ClientKeys getClientKeys(CMTestStoreProvider tp2) throws Exception {
        return (OA2ClientKeys) getClientConverter(tp2).getKeys();
    }

    public final String DD = "----------------------------------------------------------------------------";

    public void x() {
        System.out.println(DD);
    }

    protected void prettyPrint(JSONObject api) {
        String out = JSONUtils.valueToString(api, 1, 0);
        System.out.println(out);
        x();
    }

    protected Client getClient(ClientStore store) {
        Client c = (Client) store.create();
        String random = getRandom(8);
        c.setSecret(getRandom(64));
        c.setProxyLimited(true);
        c.setHomeUri("https://baz.foo.edu/" + random + "/home");
        c.setErrorUri("https://baz.foo.edu/home/" + random + "/error");
        c.setProxyLimited(false);
        c.setEmail("bob@" + random + ".foo.bar");
        c.setName("Test client " + random);
        return c;
    }

    protected AdminClient getAdminClient(AdminClientStore store) {
        AdminClient adminClient = (AdminClient) store.create();
        String random = getRandom(8);
        adminClient.setSecret(getRandom(64));
        adminClient.setName("Test admin client " + random);
        adminClient.setEmail("bob@" + random + ".foo.bar");
        adminClient.setVirtualOrganization("VO=" + getRandom(64));
        adminClient.setIssuer("Issuer=" + random);
        store.save(adminClient);
        return adminClient;
    }

    protected OA2Client getOa2Client(ClientStore store) {
        OA2Client c = (OA2Client) store.create();
        String random = getRandom(8);
        c.setSecret(getRandom(64));
        c.setProxyLimited(true);
        c.setHomeUri("https://baz.foo.edu/" + random + "/home");
        c.setErrorUri("https://baz.foo.edu/home/" + random + "/error");
        c.setProxyLimited(false);
        c.setEmail("bob@" + random + ".foo.bar");
        c.setName("Test client " + random);
        c.setRtLifetime(456767875477L);

        LinkedList<String> callbacks = new LinkedList<>();
        callbacks.add("https:/baz.foo.edu/client2/" + random + "/ready1");
        callbacks.add("https:/baz.foo.edu/client2/" + random + "/ready2");
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
        store.save(c);
        return c;
    }

}
