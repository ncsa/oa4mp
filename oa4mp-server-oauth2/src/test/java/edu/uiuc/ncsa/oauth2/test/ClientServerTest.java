package edu.uiuc.ncsa.oauth2.test;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.RequestFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.client.*;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.AddClientRequest;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.PermissionServer;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.TypeClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.TypePermission;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ClientConverter;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ClientKeys;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.Date;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/2/16 at  11:25 AM
 */
public class ClientServerTest extends DDServerTests {
    @Override
    public void testAll(CMTestStoreProvider tp2) throws Exception {
        testApprove(tp2);
        testUnapprove(tp2);
        testCreate(tp2);
        testRemove(tp2);
    }

    public void testApprove(CMTestStoreProvider tp2) throws Exception {
        CC cc = setupClients(tp2);
        ApproveRequest req = RequestFactory.createRequest(cc.adminClient, new TypeClient(), new ActionApprove(), cc.client, null);
        ClientServer server = new ClientServer(tp2.getCOSE());
        ClientResponse resp = (ClientResponse) server.process(req);
        ClientApproval approval = tp2.getClientApprovalStore().get(cc.client.getIdentifier());
        assert approval != null : "No approval found";
        assert approval.isApproved();
    }

    public void testUnapprove(CMTestStoreProvider tp2) throws Exception {
        CC cc = setupClients(tp2);
        // approve it first.
        ApproveRequest req0 = RequestFactory.createRequest(cc.adminClient, new TypeClient(), new ActionApprove(), cc.client, null);
        ClientServer server = new ClientServer(tp2.getCOSE());
        ClientResponse resp0 = (ClientResponse) server.process(req0);


        UnapproveRequest req = RequestFactory.createRequest(cc.adminClient, new TypeClient(), new ActionUnapprove(), cc.client, null);
        ClientResponse resp = (ClientResponse) server.process(req);
        ClientApproval approval = tp2.getClientApprovalStore().get(cc.client.getIdentifier());
        assert approval != null : "No approval found";
        assert !approval.isApproved();
    }

    /**
     * We cannot just do a put all to pull the objects from a columnMap (e.g.) to a JSON object
     * because JSON will convert the objects to their component parts (e.g. a URL is going to end up
     * with its fragment, server and a bunch of other fields explicitly given), which makes converting back very hard.
     * @param map
     * @param json
     */
     protected void jsonToMap(JSONObject json, Map<String, Object> map){
         for(Object key: json.keySet()){
                Object value = json.get(key);
             if(value instanceof String){
                 map.put(key.toString(), value);
             }
             if(value instanceof Date){
                 map.put(key.toString(), Iso8601.date2String((Date)value));
             }
             if(value instanceof JSONArray){
                 map.put(key.toString(), ((JSONArray) value).toArray());
             }
         }

     }

    public void testCreate(CMTestStoreProvider tp2) throws Exception{
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
        JSONObject json = new JSONObject();
        json.putAll(values);

        CreateRequest req = RequestFactory.createRequest(cc.adminClient, new TypeClient(), new ActionCreate(), null, json);
        ClientServer server = new ClientServer(tp2.getCOSE());
        CreateResponse resp = (CreateResponse) server.process(req);
        OA2Client newClient = resp.getClient();
        assert tp2.getClientStore().containsKey(newClient.getIdentifier());
        // quick and dirty check
        OA2Client oldClient = (OA2Client)cc.client;
        oldClient.setIdentifier(newClient.getIdentifier());
        oldClient.setSecret(newClient.getSecret());
        assert oldClient.equals(newClient);
    }

    public void testRemove(CMTestStoreProvider tp2) throws Exception{
        CC cc = setupClients(tp2);
        // so approve this
        ClientServer server = new ClientServer(tp2.getCOSE());
        ApproveRequest approveRequest = RequestFactory.createRequest(cc.adminClient, new TypeClient(), new ActionApprove(), cc.client, null);
        server.process(approveRequest);
        assert tp2.getClientApprovalStore().containsKey(cc.client.getIdentifier());
        assert tp2.getClientApprovalStore().get(cc.client.getIdentifier()).isApproved();
        assert !tp2.getPermissionStore().get(cc.adminClient.getIdentifier(), cc.client.getIdentifier()).isEmpty();

        AdminClient ac2 = getAdminClient(tp2.getAdminClientStore());
        PermissionServer permissionServer = new PermissionServer(tp2.getCOSE());
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





    }
}
