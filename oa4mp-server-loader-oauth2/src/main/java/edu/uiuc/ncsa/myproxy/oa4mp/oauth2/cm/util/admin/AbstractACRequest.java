package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.admin;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.delegation.services.Request;
import edu.uiuc.ncsa.security.delegation.services.Response;
import edu.uiuc.ncsa.security.delegation.services.Server;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/17/17 at  10:51 AM
 */
public class AbstractACRequest implements Request {
    public AbstractACRequest(AdminClient adminClient) {
        this.adminClient = adminClient;
    }

    AdminClient adminClient;

    /**
     * The admin client (may be partial) that was sent with this request.
     * @return
     */
    public AdminClient getAdminClient() {
        return adminClient;
    }

    public void setAdminClient(AdminClient adminClient) {
        this.adminClient = adminClient;
    }

    @Override
    public Response process(Server server) {
        if (server instanceof AdminClientServer) {
            AdminClientServer x = (AdminClientServer) server;
            if (this instanceof ACGetRequest) {
                return x.get((ACGetRequest) this);
            }
        }
        throw new NFWException("Incorrect server is invoking this method. Expected a ClientServer and got a " + server.getClass().getSimpleName());

    }
}
