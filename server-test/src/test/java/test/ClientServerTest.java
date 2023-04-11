package test;

import edu.uiuc.ncsa.myproxy.oa4mp.TestStoreProviderInterface;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.RequestFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.client.*;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.AddClientRequest;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.PermissionServer;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientConverter;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.TypeClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.TypePermission;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.Date;
import java.util.Map;

/**
 * Tests for the OA4MP client management API. These test the request framework i.e. that
 * generating various types of requests all are resolved properly and work as expected.)
 * This does not test RFC 7591/7592.
 * <p>Created by Jeff Gaynor<br>
 * on 12/2/16 at  11:25 AM
 */
public class ClientServerTest extends DDServerTests {
    @Override
    public void testAll(TestStoreProviderInterface tp2) throws Exception {
        testApprove(tp2);
        testUnapprove(tp2);
        testCreate(tp2);
        testCreatePublicClient(tp2);
        testRemove(tp2);
        CIL698(tp2);
    }

    public void testApprove(TestStoreProviderInterface tp2) throws Exception {
        CC cc = setupClients(tp2);
        ApproveRequest req = RequestFactory.createRequest(cc.adminClient, new TypeClient(), new ActionApprove(), cc.client, null);
        ClientServer server = new ClientServer((OA2SE) tp2.getSE());
        ClientResponse resp = (ClientResponse) server.process(req);
        ClientApproval approval = tp2.getClientApprovalStore().get(cc.client.getIdentifier());
        assert approval != null : "No approval found";
        assert approval.isApproved();
        cleanupCC(cc, tp2);

    }

    public void testUnapprove(TestStoreProviderInterface tp2) throws Exception {
        CC cc = setupClients(tp2);
        // approve it first.
        ApproveRequest req0 = RequestFactory.createRequest(cc.adminClient, new TypeClient(), new ActionApprove(), cc.client, null);
        ClientServer server = new ClientServer((OA2SE) tp2.getSE());
        ClientResponse resp0 = (ClientResponse) server.process(req0);


        UnapproveRequest req = RequestFactory.createRequest(cc.adminClient, new TypeClient(), new ActionUnapprove(), cc.client, null);
        ClientResponse resp = (ClientResponse) server.process(req);
        ClientApproval approval = tp2.getClientApprovalStore().get(cc.client.getIdentifier());
        assert approval != null : "No approval found";
        assert !approval.isApproved();
        cleanupCC(cc, tp2);
    }

    /**
     * We cannot just do a put all to pull the objects from a columnMap (e.g.) to a JSON object
     * because JSON will convert the objects to their component parts (e.g. a URL is going to end up
     * with its fragment, server and a bunch of other fields explicitly given), which makes converting back very hard.
     *
     * @param map
     * @param json
     */
    protected void jsonToMap(JSONObject json, Map<String, Object> map) {
        for (Object key : json.keySet()) {
            Object value = json.get(key);
            if (value instanceof String) {
                map.put(key.toString(), value);
            }
            if (value instanceof Date) {
                map.put(key.toString(), Iso8601.date2String((Date) value));
            }
            if (value instanceof JSONArray) {
                map.put(key.toString(), ((JSONArray) value).toArray());
            }
        }

    }

    /**
     * Bug introduced in 4.1.1: Trying to limit making too many clients resulted in a limit
     * of a single client being creatable. This will create several as a check.
     *
     * @param tp2
     * @throws Exception
     */
    public void CIL698(TestStoreProviderInterface tp2) throws Exception {
        int numberOfClients = 5;
        CC cc = setupClients(tp2);
        OA2ClientConverter converter = getClientConverter(tp2);
        ColumnMap values = new ColumnMap();
        converter.toMap(cc.client, values);
        tp2.getClientStore().remove(cc.client.getIdentifier());
        assert !tp2.getClientStore().containsKey(cc.client.getIdentifier());

        // remove the identifier and create it
        OA2ClientKeys clientKeys = getClientKeys(tp2);
        values.remove(clientKeys.identifier());
        values.remove(clientKeys.creationTS());
        values.remove(clientKeys.lastModifiedTS());
        JSONObject json = new JSONObject();
        json.putAll(values);
        for(int i =0; i< numberOfClients; i++) {
            CreateRequest req = RequestFactory.createRequest(cc.adminClient, new TypeClient(), new ActionCreate(), null, json);
            ClientServer server = new ClientServer((OA2SE) tp2.getSE());
            CreateResponse resp = (CreateResponse) server.process(req);
            OA2Client newClient = resp.getClient();
            assert tp2.getClientStore().containsKey(newClient.getIdentifier());
        }
    }

    /**
     * This also tests that the new cfg attribute of the client is set.
     *
     * @param tp2
     * @throws Exception
     */
    public void testCreate(TestStoreProviderInterface tp2) throws Exception {
        // only needs an admin client and map.
        CC cc = setupClients(tp2);
        OA2ClientConverter converter = getClientConverter(tp2);
        ColumnMap values = new ColumnMap();
        converter.toMap(cc.client, values);
        tp2.getClientStore().remove(cc.client.getIdentifier());
        assert !tp2.getClientStore().containsKey(cc.client.getIdentifier());

        // remove the identifier and create it
        OA2ClientKeys clientKeys = getClientKeys(tp2);
        values.remove(clientKeys.identifier());
        values.remove(clientKeys.creationTS());
        values.remove(clientKeys.lastModifiedTS());
        JSONObject json = new JSONObject();
        json.putAll(values);

        CreateRequest req = RequestFactory.createRequest(cc.adminClient, new TypeClient(), new ActionCreate(), null, json);
        ClientServer server = new ClientServer((OA2SE) tp2.getSE());
        CreateResponse resp = (CreateResponse) server.process(req);
        OA2Client newClient = resp.getClient();
        assert tp2.getClientStore().containsKey(newClient.getIdentifier());
        // quick and dirty check
        OA2Client oldClient = (OA2Client) cc.client;
        oldClient.setIdentifier(newClient.getIdentifier());
        oldClient.setSecret(newClient.getSecret());
        // Make sure cfg is correct.
        JSONObject cfg1 = oldClient.getConfig();
        JSONObject cfg2 = newClient.getConfig();
        assert cfg1.getString("version").equals(cfg2.getString("version")) : "Configurations do not match in OA2 clients";
        assert oldClient.equals(newClient);
        cleanupCC(cc, tp2);

    }


    public void testCreatePublicClient(TestStoreProviderInterface tp2) throws Exception {
        // only needs an admin client and map.
        CC cc = setupClients(tp2);
        cc.client.setPublicClient(true);
        tp2.getClientStore().save(cc.client);

        OA2ClientConverter converter = getClientConverter(tp2);
        ColumnMap values = new ColumnMap();
        converter.toMap(cc.client, values);
        tp2.getClientStore().remove(cc.client.getIdentifier());
        assert !tp2.getClientStore().containsKey(cc.client.getIdentifier());

        // remove the identifier and create it
        OA2ClientKeys clientKeys = getClientKeys(tp2);
        values.remove(clientKeys.identifier());
        values.remove(clientKeys.creationTS());
        JSONObject json = new JSONObject();
        json.putAll(values);

        CreateRequest req = RequestFactory.createRequest(cc.adminClient, new TypeClient(), new ActionCreate(), null, json);
        ClientServer server = new ClientServer((OA2SE) tp2.getSE());
        CreateResponse resp = (CreateResponse) server.process(req);
        OA2Client newClient = resp.getClient();
        assert tp2.getClientStore().containsKey(newClient.getIdentifier());
        // quick and dirty check
        OA2Client oldClient = (OA2Client) cc.client;
        oldClient.setIdentifier(newClient.getIdentifier());
        oldClient.setSecret(newClient.getSecret());
        assert oldClient.equals(newClient);
        cleanupCC(cc, tp2);

    }


    public void testRemove(TestStoreProviderInterface tp2) throws Exception {
        CC cc = setupClients(tp2);
        // so approve this
        ClientServer server = new ClientServer((OA2SE) tp2.getSE());
        ApproveRequest approveRequest = RequestFactory.createRequest(cc.adminClient, new TypeClient(), new ActionApprove(), cc.client, null);
        server.process(approveRequest);
        assert tp2.getClientApprovalStore().containsKey(cc.client.getIdentifier());
        assert tp2.getClientApprovalStore().get(cc.client.getIdentifier()).isApproved();
        assert !tp2.getPermissionStore().get(cc.adminClient.getIdentifier(), cc.client.getIdentifier()).isEmpty();

        AdminClient ac2 = getAdminClient(tp2.getAdminClientStore());
        PermissionServer permissionServer = new PermissionServer((OA2SE) tp2.getSE());
        AddClientRequest addClientRequest = RequestFactory.createRequest(ac2, new TypePermission(), new ActionAdd(), cc.client, null);
        permissionServer.process(addClientRequest);
        assert !tp2.getPermissionStore().get(ac2.getIdentifier(), cc.client.getIdentifier()).isEmpty();

        // ok, so now we have a couple of admin clients with permissions on this client and it is approved. Let's
        // see if everything gets cleaned out.

        RemoveRequest removeRequest = RequestFactory.createRequest(cc.adminClient, new TypeClient(), new ActionRemove(), cc.client, null);
        server.process(removeRequest);
        assert !tp2.getClientStore().containsKey(cc.client.getIdentifier());
        assert !tp2.getClientApprovalStore().containsKey(cc.client.getIdentifier());
        assert tp2.getPermissionStore().get(cc.adminClient.getIdentifier(), cc.client.getIdentifier()).isEmpty();
        assert tp2.getPermissionStore().get(ac2.getIdentifier(), cc.client.getIdentifier()).isEmpty();

        cleanupCC(cc, tp2);

    }
}
