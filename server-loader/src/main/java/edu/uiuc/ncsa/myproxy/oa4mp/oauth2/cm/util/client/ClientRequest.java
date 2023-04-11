package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.client;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.AbstractDDRequest;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Server;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/28/16 at  1:59 PM
 */
public class ClientRequest extends AbstractDDRequest {
    public ClientRequest(AdminClient adminClient, OA2Client client) {
        super(adminClient, client);
    }

    @Override
    public Response process(Server server) {
        if (server instanceof ClientServer) {
            ClientServer x = (ClientServer) server;
            if (this instanceof ApproveRequest) {
                return x.approve((ApproveRequest) this);
            }
            if (this instanceof UnapproveRequest) {
                return x.unapprove((UnapproveRequest) this);
            }
            if (this instanceof CreateRequest) {
                return x.create((CreateRequest) this);
            }
            if(this instanceof GetRequest){
                return x.get((GetRequest)this);
            }
            if (this instanceof RemoveRequest) {
                         return x.remove((RemoveRequest) this);
                     }
        }
        throw new NFWException("Incorrect server is invoking this method. Expected a ClientServer and got a " + server.getClass().getSimpleName());

    }
}
