package test;

import org.oa4mp.server.test.TestStoreProviderInterface;
import org.oa4mp.server.test.TestUtils;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2ClientConverter;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2ClientKeys;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2ClientProvider;
import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.server.api.admin.adminClient.AdminClientConverter;
import org.oa4mp.server.api.admin.adminClient.AdminClientStore;
import org.oa4mp.server.api.admin.adminClient.AdminClientStoreProviders;
import org.oa4mp.server.api.admin.permissions.Permission;
import org.oa4mp.server.api.admin.permissions.PermissionList;
import org.oa4mp.server.api.admin.transactions.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.common.storage.clients.BaseClientConverter;
import org.oa4mp.delegation.server.OA2Scopes;
import org.oa4mp.delegation.server.server.config.LDAPConfiguration;
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
    public abstract void testAll(TestStoreProviderInterface tp2) throws Exception;

    public void testMemoryStore() throws Exception {
        testAll(TestUtils.getMemoryStoreProvider());
    }

    public void testFilestore() throws Exception {
        testAll(TestUtils.getFsStoreProvider());
    }

    public void testMysql() throws Exception {
        testAll(TestUtils.getMySQLStoreProvider());
    }

    public void testPostgres() throws Exception {
        testAll(TestUtils.getPgStoreProvider());
    }

    public void testDerby() throws Exception {
        testAll(TestUtils.getDerbyStoreProvider());
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

    /**
     * Thsi will take a test store provider and create a {@link test.DDServerTests.CC} (configured clients) object.
     * That contains an admin client and an associated pre-approved client for it. It has set the permissions as well
     * so that admin client can perform operations on the client. Note that the client is not pre-populated with
     * any information, but there is an approval record for it (approver is "junit").<br/>
     * Every timne you call this you should balance it with a call to {@link #cleanupCC(CC, TestStoreProviderInterface)}.
     * Typically this is one fo the very first calls in a test, cleanup is the very last.
     *
     * @param tp2
     * @return
     * @throws Exception
     */
    protected CC setupClients(TestStoreProviderInterface tp2) throws Exception {
        AdminClient adminClient = getAdminClient(tp2.getAdminClientStore());
        ClientApproval clientApproval = tp2.getClientApprovalStore().create();
        clientApproval.setIdentifier(adminClient.getIdentifier());
        clientApproval.setApproved(true);
        clientApproval.setApprover("junit");
        tp2.getClientApprovalStore().save(clientApproval);

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

    /**
     * Clean up a configured clients object at the end of test.  Typically every time you call {@link #setupClients(TestStoreProviderInterface)}
     * you should call this or you will accumulate a ton of various clients and permissions that can only be removed by
     * twiddling the database directly.<br/>
     * This tries to be very robust and aggressive when removing things in the assumption that the admin and client
     * exist only rfor the duration of a specific test. Since the test state is unknown (e.g. You may have tested
     * deleting the client so that fails) this only spits out messages noting what did not work, rather than failing.
     *
     * @param cc
     * @param tp2
     */
    protected void cleanupCC(CC cc, TestStoreProviderInterface tp2) {
        try {
            // get rid of permissions
            PermissionList pList = tp2.getPermissionStore().get(cc.adminClient.getIdentifier(), cc.client.getIdentifier());
            for (Permission p : pList) {
                tp2.getPermissionStore().remove(p.getIdentifier());
            }
        } catch (Throwable t) {
            System.out.println("NOTE: Could not remove permissions for client \"" + cc.client.getIdentifierString() + "\" and admin \"" + cc.adminClient.getIdentifierString() + "\"," +
                    ":" + t.getMessage());
        }
        try {
            // remove the approval
            tp2.getClientApprovalStore().remove(cc.client.getIdentifier());
        } catch (Throwable t) {
            System.out.println("NOTE: remove client approval for \"" + cc.client.getIdentifierString() + "\" and admin \"" + cc.adminClient.getIdentifierString() + "\"," +
                    ":" + t.getMessage());
        }
        try {
            // remove the client
            tp2.getClientStore().remove(cc.client.getIdentifier());
        } catch (Throwable t) {
            System.out.println("NOTE: Could not remove client with id \"" + cc.client.getIdentifierString() + "\" and admin \"" + cc.adminClient.getIdentifierString() + "\"," +
                    ":" + t.getMessage());
        }
        try {
            // remove the admin.
            tp2.getAdminClientStore().remove(cc.adminClient.getIdentifier());
        } catch (Throwable t) {
            System.out.println("NOTE: Could not remove admin client \"" + cc.adminClient.getIdentifierString() + "\"," + ":" + t.getMessage());
        }
    }

    protected AdminClientConverter getAdminClientConverter(TestStoreProviderInterface tp2) throws Exception {
        BaseClientConverter bcc = (BaseClientConverter) tp2.getAdminClientStore().getMapConverter();
        if (bcc instanceof AdminClientConverter) {
            return (AdminClientConverter) bcc;
        }

        return AdminClientStoreProviders.getAdminClientConverter();
    }

    protected OA2ClientConverter getClientConverter(TestStoreProviderInterface tp2) throws Exception {
        BaseClientConverter bcc = (BaseClientConverter) tp2.getClientStore().getMapConverter();
        if (bcc instanceof OA2ClientConverter) {
            return (OA2ClientConverter) bcc;
        }
        // In the weird chance something does not have one, the default is provided.
        OA2ClientProvider clientProvider = new OA2ClientProvider(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.CLIENT_ID));
        OA2ClientConverter converter = new OA2ClientConverter(clientProvider);

        return converter;
    }

    protected OA2ClientKeys getClientKeys(TestStoreProviderInterface tp2) throws Exception {
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
        adminClient.setVirtualOrganization(BasicIdentifier.randomID());
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
        JSONObject cfg = new JSONObject();
        cfg.put("version", getRandom());
        c.setConfig(cfg);

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
