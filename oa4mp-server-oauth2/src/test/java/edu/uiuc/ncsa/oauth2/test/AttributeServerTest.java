package edu.uiuc.ncsa.oauth2.test;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.RequestFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.attributes.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.ActionGet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.ActionRemove;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.ActionSet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.TypeAttribute;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ClientKeys;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.LinkedList;


/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/1/16 at  10:43 AM
 */
public class AttributeServerTest extends DDServerTests {
    public void testAll(CMTestStoreProvider tp2) throws Exception {
        testAttributeServerGet(tp2);
        testAttributeServerSet(tp2);
        testAttributeServerRemove(tp2);
    }

    public void testAttributeServerGet(CMTestStoreProvider tp2) throws Exception {
        CC cc = setupClients(tp2);

        AttributeServer attributeServer = new AttributeServer(tp2.getCOSE());
        OA2ClientKeys keys = getClientKeys(tp2);
        JSONArray array = new JSONArray();
        array.add(keys.scopes());
        array.add(keys.callbackUri());
        array.add(keys.rtLifetime());
        array.add(keys.name());

        AttributeGetRequest req = RequestFactory.createRequest(cc.adminClient, new TypeAttribute(), new ActionGet(), cc.client, array);
        AttributeClientResponse r = (AttributeClientResponse) attributeServer.process(req);
        OA2Client reducedClient = (OA2Client) r.getClient();
        assert reducedClient.getIdentifier().equals(cc.client.getIdentifier());
        assert reducedClient.getScopes() != null;
        assert reducedClient.getCallbackURIs() != null;
        assert reducedClient.getRtLifetime() == cc.client.getRtLifetime();
        assert reducedClient.getName().equals(cc.client.getName());

        JSONObject json = new JSONObject();
        tp2.getClientStore().getACConverter().toJSON(r.getClient(), json);
        System.out.println(json);
    }

    public void testAttributeServerSet(CMTestStoreProvider tp2) throws Exception {
        CC cc = setupClients(tp2);
        OA2ClientKeys keys = getClientKeys(tp2);
        AttributeServer attributeServer = new AttributeServer(tp2.getCOSE());
        JSONObject map = new JSONObject();
        String random = getRandom(8);
        LinkedList<String> scopes = new LinkedList<>();
        scopes.add(OA2Scopes.SCOPE_PROFILE);
        scopes.add(OA2Scopes.SCOPE_OPENID);

        map.put(keys.name(), "new name " + random);
        map.put(keys.homeURL(), "https://" + random + "/client");
        map.put(keys.scopes(), scopes);
        AttributeSetClientRequest req = RequestFactory.createRequest(cc.adminClient, new TypeAttribute(), new ActionSet(), cc.client, map);
        AttributeClientResponse resp = (AttributeClientResponse) attributeServer.process(req);
        OA2Client client = (OA2Client) resp.getClient();
        assert client.getName().equals(map.get(keys.name()));
        assert client.getIdentifier().equals(cc.client.getIdentifier());
        assert client.getHomeUri().equals(map.get(keys.homeURL()));
        assert client.getScopes().size() == scopes.size();
        for (String scope : scopes) {
            assert client.getScopes().contains(scope) : "returned scopes failed to contain " + scope;
        }
    }

    public void testAttributeServerRemove(CMTestStoreProvider tp2) throws Exception {
        CC cc = setupClients(tp2);
        AttributeServer attributeServer = new AttributeServer(tp2.getCOSE());
        OA2ClientKeys keys = getClientKeys(tp2);

        JSONArray attributes = new JSONArray();
        attributes.add(keys.homeURL());
        attributes.add(keys.email());
        attributes.add(keys.rtLifetime());
        attributes.add(keys.scopes());
        AttributeRemoveRequest req = RequestFactory.createRequest(cc.adminClient, new TypeAttribute(), new ActionRemove(), cc.client, attributes);
        AttributeClientResponse resp = (AttributeClientResponse) attributeServer.process(req);
        OA2Client client = (OA2Client) resp.getClient();
        assert client.getScopes() == null || client.getScopes().isEmpty();
        assert client.getRtLifetime() == 0L;
        assert client.getHomeUri() == null;
        assert client.getEmail() == null;
    }
}
