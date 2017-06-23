package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.attributes;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.loader.COSE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.AbstractDDServer;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientConverter;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.services.Response;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ClientConverter;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;

/**
 * This server handles various requests for attributes.
 * <p>Created by Jeff Gaynor<br>
 * on 11/28/16 at  1:31 PM
 */
public class AttributeServer extends AbstractDDServer {
    public AttributeServer(COSE cose) {
        super(cose);
    }


    public Response get(AttributeGetRequest request) {
        if (request.getClient() != null) {
            return getClientAttributes(request);
        }

        if (request.hasAdminClient()) {
            return getAdminClientAttributes(request);
        }

        throw new GeneralException("Error: No admin client");

    }

    protected AttributeClientResponse getClientAttributes(AttributeGetRequest request) {
        canRead(request);
        OA2Client fullclient = (OA2Client) getClientStore().get(request.getClient().getIdentifier());
        AttributeGetClientResponse response = new AttributeGetClientResponse(subset(fullclient, request.attributes), request.attributes);
        return response;

    }

    protected AttributeGetAdminClientResponse getAdminClientAttributes(AttributeGetRequest request) {
        AdminClient adminClient = getAdminClientStore().get(request.getAdminClient().getIdentifier());
        AttributeGetAdminClientResponse response = new AttributeGetAdminClientResponse(subset(adminClient, request.attributes), request.attributes);
        return response;

    }

    protected OA2ClientConverter getClientConverter() {
        return (OA2ClientConverter) cose.getClientStore().getACConverter();
    }

    protected AdminClientConverter getACConverter() {
        return (AdminClientConverter) cose.getAdminClientStore().getACConverter();
    }

    public Response set(AttributeSetClientRequest request) {
        if (request.hasClient()) {
            return setClientAttribute(request);
        }

        if (request.hasAdminClient()) {
            //throw new GeneralException("Error: no admin client");
            return setAdminClientAttribute(request);
        }
        throw new GeneralException("Error: Neither client nor admin given.");
    }

    protected AttributeClientResponse setClientAttribute(AttributeSetClientRequest request) {
        canWrite(request);
        OA2Client client = (OA2Client) getClientStore().get(request.getClient().getIdentifier());
        ColumnMap map = new ColumnMap();
        getClientConverter().toMap(client, map);
        for (String key : request.getAttributes().keySet()) {
            // don't let anyone change the identifier.
            if (!key.equals(getClientConverter().getKeys().identifier())) {
                map.put(key, request.getAttributes().get(key));
            }
        }
        OA2Client updatedClient = getClientConverter().fromMap(map, null);
        getClientStore().save(updatedClient);
        AttributeClientResponse attributeClientResponse = new AttributeClientResponse(updatedClient);
        return attributeClientResponse;
    }

    protected AttributeAdminClientResponse setAdminClientAttribute(AttributeSetClientRequest request) {
        AdminClient client = getAdminClientStore().get(request.getAdminClient().getIdentifier());
        ColumnMap map = new ColumnMap();
        getACConverter().toMap(client, map);
        for (String key : request.getAttributes().keySet()) {
            // don't let anyone change the identifier.
            if (!key.equals(getACConverter().getKeys().identifier())) {
                map.put(key, request.getAttributes().get(key));
            }
        }
        AdminClient updatedClient = getACConverter().fromMap(map, null);
        getAdminClientStore().save(updatedClient);
        AttributeAdminClientResponse attributeClientResponse = new AttributeAdminClientResponse(updatedClient);
        return attributeClientResponse;
    }

    public Response remove(AttributeRemoveRequest request) {
        if(request.hasClient()){
            return removeClient(request);
        }
        if (request.hasAdminClient()) {
            return removeAdminClient(request);

        }
        throw new GeneralException("Error: No admin client or client");

    }

    /**
     * Remove a subset of attributes for client.
     *
     * @param request
     * @return
     */
    protected AttributeClientResponse removeClient(AttributeRemoveRequest request) {
        canWrite(request);
        OA2Client client = (OA2Client) getClientStore().get(request.getClient().getIdentifier());

        ColumnMap map = new ColumnMap();
        getClientConverter().toMap(client, map);
        for (String key : request.getAttributes()) {
            // don't let anyone change the identifier.
            if (!key.equals(getClientConverter().getKeys().identifier())) {
                map.remove(key);
            }
        }
        OA2Client updatedClient = getClientConverter().fromMap(map, null);
        getClientStore().save(updatedClient);
        AttributeClientResponse attributeClientResponse = new AttributeClientResponse(updatedClient);
        return attributeClientResponse;
    }

    /**
     * Remove a subset of attributes for an admin client.
     *
     * @param request
     * @return
     */
    protected AttributeAdminClientResponse removeAdminClient(AttributeRemoveRequest request) {
        AdminClient client = getAdminClientStore().get(request.getAdminClient().getIdentifier());

        ColumnMap map = new ColumnMap();
        getACConverter().toMap(client, map);
        for (String key : request.getAttributes()) {
            // don't let anyone change the identifier.
            if (!key.equals(getACConverter().getKeys().identifier())) {
                map.remove(key);
            }
        }
        AdminClient updatedClient = getACConverter().fromMap(map, null);
        getAdminClientStore().save(updatedClient);
        AttributeAdminClientResponse attributeClientResponse = new AttributeAdminClientResponse(updatedClient);
        return attributeClientResponse;
    }


}
