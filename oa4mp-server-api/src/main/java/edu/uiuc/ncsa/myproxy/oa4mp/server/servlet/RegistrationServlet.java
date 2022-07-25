package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.util.NewClientEvent;
import edu.uiuc.ncsa.security.core.exceptions.RetryException;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.servlet.Presentable;
import edu.uiuc.ncsa.security.util.crypto.KeyUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The servlet that handles registration. This will create the correct state then forward the request to the correct JSP
 * page. Since this implements the {@link Presentable} interface, you may over-ride it to display information anyway you wish.
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/11 at  3:53 PM
 */
public class RegistrationServlet extends AbstractRegistrationServlet {
    @Override
    protected Client addNewClient(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        Client client = (Client)super.addNewClient(request, response);
        client.setSecret(getRequiredParam(request, CLIENT_PUBLIC_KEY, client));
        String x = getRequiredParam(request, CLIENT_ERROR_URL, client);
        if(!x.toLowerCase().startsWith("https")){
            throw new RetryException("The error uri \"" + x + "\" is not secure.");
        }
        client.setErrorUri(x);
        try {
            debug("decoding public key from PEM");
            KeyUtil.fromX509PEM(client.getSecret());
        } catch (Throwable t) {
            warn("could not decode public key for client=" + client.getIdentifierString() + ", message:" + t.getMessage());
            request.setAttribute("client", client);
            throw new RetryException("public key could not be parsed. " + t.getMessage());
        }
        fireNewClientEvent(new NewClientEvent(this,client));
        return client;
    }
}
