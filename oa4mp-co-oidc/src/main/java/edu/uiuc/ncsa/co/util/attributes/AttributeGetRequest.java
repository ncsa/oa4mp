package edu.uiuc.ncsa.co.util.attributes;


import edu.uiuc.ncsa.co.util.AbstractDDRequest;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.*;
import edu.uiuc.ncsa.security.delegation.services.Response;
import edu.uiuc.ncsa.security.delegation.services.Server;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/28/16 at  1:32 PM
 */
public class AttributeGetRequest extends AbstractDDRequest {
    public AttributeGetRequest(Action action,
                               AdminClient adminClient,
                               OA2Client client,
                               List<String> attributes) {
        super(action,adminClient,client);
        this.attributes = attributes;
    }

    public List<String> getAttributes() {
        return attributes;
    }

    List<String> attributes;


    @Override
    public Response process(Server server) {
        if(server instanceof AttributeServer){
            AttributeServer attributeServer = (AttributeServer) server;
            if(action instanceof ActionGet){
                return attributeServer.get(this);
            }
            if(action instanceof ActionSet){
                return attributeServer.set(this);
            }
            if(action instanceof ActionRemove){
                return attributeServer.remove(this);
            }
            if(action instanceof ActionList){
                return attributeServer.list(this);
            }
        }
        return null;
    }
}
