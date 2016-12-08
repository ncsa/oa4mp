package edu.uiuc.ncsa.co.util;

import edu.uiuc.ncsa.co.loader.COSE;
import edu.uiuc.ncsa.co.util.attributes.AttributeResponse;
import edu.uiuc.ncsa.co.util.client.ClientResponse;
import edu.uiuc.ncsa.co.util.client.CreateResponse;
import edu.uiuc.ncsa.co.util.client.GetResponse;
import edu.uiuc.ncsa.co.util.permissions.ListAdminsResponse;
import edu.uiuc.ncsa.co.util.permissions.ListClientResponse;
import edu.uiuc.ncsa.co.util.permissions.PermissionResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.delegation.services.Response;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ClientKeys;
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
    COSE cose;

    public ResponseSerializer(COSE cose) {
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
        if (response instanceof AttributeResponse) {
            serialize((AttributeResponse) response, servletResponse);
            return;
        }

        if (response instanceof Permission) {
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

    protected void serialize(AttributeResponse response, HttpServletResponse servletResponse) throws IOException {
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
        OA2ClientKeys keys = (OA2ClientKeys) cose.getClientStore().getACConverter().getKeys();
        List<String> allKeys = keys.allKeys();
        allKeys.remove(keys.secret());
        OA2Client newClient = (OA2Client) cose.getClientStore().getACConverter().subset(client, allKeys);
        JSONObject jsonClient = new JSONObject();
        cose.getClientStore().getACConverter().toJSON(newClient, jsonClient);
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
