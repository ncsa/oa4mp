package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.attributes;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.AbstractDDRequest;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.delegation.services.Response;
import edu.uiuc.ncsa.security.delegation.services.Server;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/30/16 at  4:16 PM
 */
public abstract class AttributeRequest extends AbstractDDRequest {
    public AttributeRequest(AdminClient adminClient, OA2Client client) {
        super(adminClient, client);
    }

    @Override
       public Response process(Server server) {
           if(server instanceof AttributeServer){
               AttributeServer attributeServer = (AttributeServer) server;
               if(this instanceof AttributeGetRequest){
                   return attributeServer.get((AttributeGetRequest) this);
               }

               if(this instanceof AttributeSetClientRequest){
                   return attributeServer.set((AttributeSetClientRequest) this);
               }

               if(this instanceof AttributeRemoveRequest){
                   return attributeServer.remove((AttributeRemoveRequest) this);
               }

               throw new GeneralException("Action not supported");
           }
        throw new NFWException("Incorrect server is invoking this method. Expected an AttributeServer and got a " + server.getClass().getSimpleName());

       }

}
