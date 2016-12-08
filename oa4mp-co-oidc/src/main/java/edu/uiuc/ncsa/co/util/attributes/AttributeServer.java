package edu.uiuc.ncsa.co.util.attributes;

import edu.uiuc.ncsa.co.loader.COSE;
import edu.uiuc.ncsa.co.util.AbstractDDServer;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientConverter;
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



    public AttributeResponse get(AttributeGetRequest request) {
        canRead(request);

        AttributeResponse response = new AttributeResponse(subset(request.getClient(), request.attributes));
        return response;
    }

    protected OA2ClientConverter getClientConverter(){return (OA2ClientConverter) cose.getClientStore().getACConverter();}

    protected AdminClientConverter getACConverter(){return (AdminClientConverter) cose.getAdminClientStore().getACConverter();}
    public AttributeResponse set(AttributeSetRequest request) {
        canWrite(request);
        OA2Client client = (OA2Client) getClientStore().get(request.getClient().getIdentifier());
        ColumnMap map = new ColumnMap();
        getClientConverter().toMap(client, map);
        for(String key : request.getAttributes().keySet()){
        // don't let anyone change the identifier.
             if(!key.equals(getClientConverter().getKeys().identifier())) {
                 map.put(key, request.getAttributes().get(key));
             }
        }
        OA2Client updatedClient = getClientConverter().fromMap(map, null);
        getClientStore().save(updatedClient);
        AttributeResponse attributeResponse = new AttributeResponse(updatedClient);
        return attributeResponse;
    }

    public AttributeResponse remove(AttributeRemoveRequest request) {
        canWrite(request);
        OA2Client client = (OA2Client) getClientStore().get(request.getClient().getIdentifier());

        ColumnMap map = new ColumnMap();
        getClientConverter().toMap(client, map);
        for(String key : request.getAttributes()){
        // don't let anyone change the identifier.
             if(!key.equals(getClientConverter().getKeys().identifier())) {
                 map.remove(key);
             }
        }
        OA2Client updatedClient = getClientConverter().fromMap(map, null);
        getClientStore().save(updatedClient);
        AttributeResponse attributeResponse = new AttributeResponse(updatedClient);
        return attributeResponse;
    }

    public OA2Client getAll(AttributeGetRequest request) {
        return request.getClient();
    }


}
