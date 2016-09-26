package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.security.delegation.storage.Client;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This will <i>automatically</i> approve every client request. And is intended
 * to allow administrators to test their installation. <B>Do not use in a production environment!!</B>
 * <h2>Use</h2>
 * Point to this in the descriptor instead of {@link edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.RegistrationServlet}
 * <b>NOTE:</b> Can't stress enough that this is a debug tool for testing deployments and is inherently unsafe in
 * a production environment.
 * <p>Created by Jeff Gaynor<br>
 * on 9/28/11 at  1:20 PM
 */
public class AutoRegistrationServlet extends RegistrationServlet {
    @Override
    protected Client addNewClient(HttpServletRequest request, HttpServletResponse response) throws Throwable{
        Client client = super.addNewClient(request, response);
        if(client != null){
            approveClient(client.getIdentifier(), "auto-approver");
        }
        fireNewClientEvent(client);
        return client;
    }
}
