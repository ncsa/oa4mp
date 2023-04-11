package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.admin.ACGetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.attributes.AttributeAdminClientResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.attributes.AttributeClientResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.attributes.AttributeGetAdminClientResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.attributes.AttributeGetClientResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.client.ClientResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.client.CreateResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.client.GetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.AddClientResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.ListAdminsResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.ListClientResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.PermissionResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientConverter;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientConverter;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientKeys;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/6/16 at  10:10 AM
 */
public class ResponseSerializer {
    OA2SE cose;

    public ResponseSerializer(OA2SE cose) {
        this.cose = cose;
    }

    public void serialize(Response response, HttpServletResponse servletResponse) throws IOException {
        if (response instanceof GetResponse) {
            serialize((GetResponse) response, servletResponse);
            return;
        }

        if (response instanceof CreateResponse) {
            serialize((CreateResponse) response, servletResponse);
            return;
        }
        if (response instanceof ListClientResponse) {
            serialize((ListClientResponse) response, servletResponse);
            return;
        }
        if (response instanceof ListAdminsResponse) {
            serialize((ListAdminsResponse) response, servletResponse);
            return;
        }

        if (response instanceof ClientResponse) {
            serialize((ClientResponse) response, servletResponse);
            return;
        }

        if (response instanceof AttributeGetClientResponse) {
            serialize((AttributeGetClientResponse) response, servletResponse);
            return;
        }
        if (response instanceof AttributeClientResponse) {
            serialize((AttributeClientResponse) response, servletResponse);
            return;
        }

        if (response instanceof ACGetResponse) {
            serialize((ACGetResponse) response, servletResponse);
            return;
        }

        if (response instanceof AttributeGetAdminClientResponse) {
            serialize((AttributeGetAdminClientResponse) response, servletResponse);
            return;
        }

        if (response instanceof AttributeAdminClientResponse) {
            serialize((AttributeAdminClientResponse) response, servletResponse);
            return;
        }
        if (response instanceof AddClientResponse) {
            serialize((AddClientResponse) response, servletResponse);
            return;
        }
        if (response instanceof PermissionResponse) {
            serialize((PermissionResponse) response, servletResponse);
            return;
        }

        throw new NotImplementedException("Serialization of this response is not implemented yet");
    }

    protected void serialize(PermissionResponse response, HttpServletResponse servletResponse) throws IOException {
        ok(servletResponse);

    }


    protected void serialize(ClientResponse response, HttpServletResponse servletResponse) throws IOException {
        ok(servletResponse);

    }

    protected void serialize(AttributeGetClientResponse response, HttpServletResponse servletResponse) throws IOException {
        PrintWriter pw = servletResponse.getWriter();
        OA2ClientConverter clientConverter = (OA2ClientConverter) cose.getClientStore().getMapConverter();
        JSONObject json = new JSONObject();
        json.put("status", 0);
        OA2ClientKeys keys = (OA2ClientKeys) clientConverter.getKeys();
        List<String> allKeys = keys.allKeys();
        allKeys.remove(keys.secret());
        OA2Client newClient = (OA2Client) clientConverter.subset(response.getClient(), response.getAttributes());
        JSONObject jsonClient = new JSONObject();
        clientConverter.toJSON(newClient, jsonClient);
        if (jsonClient.getJSONObject(clientConverter.getJSONComponentName()).containsKey(keys.cfg())) {
            // clientConverter.getJSONComponentName() <--> "client"
            // keys.cfg() <--> "cfg"
            jsonClient.put(keys.cfg(), jsonClient.getJSONObject(clientConverter.getJSONComponentName()).getJSONObject(keys.cfg()));
            jsonClient.getJSONObject(clientConverter.getJSONComponentName()).remove(keys.cfg());
        }
        json.put("content", jsonClient);
        //return json;

        pw.println(json);
    }


    protected void serialize(AttributeGetAdminClientResponse response, HttpServletResponse servletResponse) throws IOException {
        PrintWriter pw = servletResponse.getWriter();
        JSONObject json = new JSONObject();
        AdminClientConverter adminClientConverter = (AdminClientConverter) cose.getAdminClientStore().getMapConverter();
        json.put("status", 0);
        AdminClientKeys keys = (AdminClientKeys) adminClientConverter.getKeys();
        List<String> allKeys = keys.allKeys();
        allKeys.remove(keys.secret());
        AdminClient newClient = (AdminClient) adminClientConverter.subset(response.getAdminClient(), response.getAttributes());
        JSONObject jsonClient = new JSONObject();
        adminClientConverter.toJSON(newClient, jsonClient);
        json.put("content", jsonClient);
        //return json;

        pw.println(json);
    }

    protected void serialize(AttributeClientResponse response, HttpServletResponse servletResponse) throws IOException {
        ok(servletResponse);
    }

    protected void serialize(AttributeAdminClientResponse response, HttpServletResponse servletResponse) throws IOException {
        ok(servletResponse);
    }

    private void ok(HttpServletResponse servletResponse) throws IOException {
        PrintWriter pw = servletResponse.getWriter();
        JSONObject json = new JSONObject();
        json.put("status", 0);
        pw.println(json);
    }

    protected void serialize(ListClientResponse response, HttpServletResponse servletResponse) throws IOException {
        JSONArray clientIDs = new JSONArray();
        if (response.getClients() != null) {
            for (OA2Client client : response.getClients()) {
                clientIDs.add(client.getIdentifierString());
            }
        }
        PrintWriter pw = servletResponse.getWriter();
        JSONObject json = new JSONObject();
        json.put("status", 0);
        json.put("content", clientIDs);
        pw.println(json);

    }

    protected void serialize(ListAdminsResponse response, HttpServletResponse servletResponse) throws IOException {
        JSONArray adminIDs = new JSONArray();
        if (response.getAdmins() != null) {
            for (AdminClient client : response.getAdmins()) {
                adminIDs.add(client.getIdentifierString());
            }
        }
        PrintWriter pw = servletResponse.getWriter();
        JSONObject json = new JSONObject();
        json.put("status", 0);
        json.put("content", adminIDs);
        pw.println(json);
    }

    protected void serialize(GetResponse response, HttpServletResponse servletResponse) throws IOException {
        PrintWriter pw = servletResponse.getWriter();
        if (response.getClient() == null) {
            pw.println("");
            return;
        }
        JSONObject json = clientToJSON(response.getClient());
        json.put("approved", response.isApproved());
        pw.println(json);

    }

    protected void serialize(ACGetResponse response, HttpServletResponse servletResponse) throws IOException {
        PrintWriter pw = servletResponse.getWriter();
        if (response.getAdminClient() == null) {
            pw.println("");
            return;
        }
        JSONObject json = acToJSON(response.getAdminClient());
        json.put("approved", response.isApproved());
        pw.println(json);

    }


    private void serializeClient(OA2Client client, HttpServletResponse servletResponse) throws IOException {
        PrintWriter pw = servletResponse.getWriter();
        if (client == null) {
            pw.println("");
        } else {
            JSONObject json = clientToJSON(client);
            pw.println(json);
        }
    }

    private JSONObject clientToJSON(OA2Client client) {
        JSONObject json = new JSONObject();
        json.put("status", 0);
        OA2ClientConverter clientConverter = (OA2ClientConverter) cose.getClientStore().getMapConverter();

        OA2ClientKeys keys = (OA2ClientKeys) clientConverter.getKeys();
        List<String> allKeys = keys.allKeys();
        allKeys.remove(keys.secret());
        OA2Client newClient = (OA2Client) clientConverter.subset(client, allKeys);
        JSONObject jsonClient = new JSONObject();
        clientConverter.toJSON(newClient, jsonClient);
        /* This would return the cfg as part of the client, so
          {
              "content": {
                  "client": {
                     "client_id": "cilogon:/client_id/520199f634205d7643f91e6fc03abaac",
                      "cfg": {...},...

           Which is inarguably correct because it allows for each client to have a unique. cfg.
           Older version (<= 4.3) assumed a global cfg like

           {
                         "content": {
                            "cfg": {...},...
                             "client": {
                                "client_id": "cilogon:/client_id/520199f634205d7643f91e6fc03abaac",

            which allowed for uploading a bunch of clients and using the same cfg for them all.
            Unfortunately, there is one user for this and this improvement breaks their code.
            (and since they only upload a single client ever at a time, the point is moot)
          */
        if (jsonClient.getJSONObject(clientConverter.getJSONComponentName()).containsKey(keys.cfg())) {
            // clientConverter.getJSONComponentName() <--> "client"
            // keys.cfg() <--> "cfg"
            jsonClient.put(keys.cfg(), jsonClient.getJSONObject(clientConverter.getJSONComponentName()).getJSONObject(keys.cfg()));
            jsonClient.getJSONObject(clientConverter.getJSONComponentName()).remove(keys.cfg());
        }
        json.put("content", jsonClient);
        return json;
    }

    private JSONObject acToJSON(AdminClient client) {
        JSONObject json = new JSONObject();
        json.put("status", 0);
        AdminClientConverter adminClientConverter = (AdminClientConverter) cose.getAdminClientStore().getMapConverter();
        AdminClientKeys keys = (AdminClientKeys) adminClientConverter.getKeys();
        List<String> allKeys = keys.allKeys();
        allKeys.remove(keys.secret());
        AdminClient newClient = (AdminClient) adminClientConverter.subset(client, allKeys);
        JSONObject jsonClient = new JSONObject();
        adminClientConverter.toJSON(newClient, jsonClient);
        json.put("content", jsonClient);
        return json;
    }


    protected void serialize(CreateResponse response, HttpServletResponse servletResponse) throws IOException {
        PrintWriter pw = servletResponse.getWriter();
        if (response.getClient() == null) {
            pw.println("");
            return;
        }
        JSONObject json = clientToJSON(response.getClient());
        json.put("secret", response.getSecret());
        servletResponse.getWriter().println(json);
    }
}
