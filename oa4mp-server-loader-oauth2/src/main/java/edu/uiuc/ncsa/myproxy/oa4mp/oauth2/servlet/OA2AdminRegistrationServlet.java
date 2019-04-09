package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractRegistrationServlet;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.storage.BaseClient;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/9/19 at  1:39 PM
 */
public class OA2AdminRegistrationServlet extends AbstractRegistrationServlet {
    @Override
    protected String getInitPage() {
         return "admin-client-registration-init.jsp";
    }

    @Override
    protected String getOKPage() {
        return "admin-client-registration-ok.jsp";
    }

    protected BaseClient setupNewClient(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        // Assumption is that the request is in good order and we just have to pull stuff off it.
        AdminClient client = ((OA2SE)getServiceEnvironment()).getAdminClientStore().create();
        info("creating entry for client=" + client.getIdentifierString());
        // Fill in as much info as we can before parsing public key.
        // We always store exactly what was given to us, though later we html escape it to
        // prevent against HTML injection attacks (fixes bug OAUTH-87).
        client.setName(getRequiredParam(request, CLIENT_NAME, client));
        String x = getRequiredParam(request, CLIENT_EMAIL, client);
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(emailPattern);
        java.util.regex.Matcher m = p.matcher(x);
        if (!m.matches()) {
            throw new ClientRegistrationRetryException("The email address \"" + x + "\" is not valid.", null, client);
        }
        client.setEmail(x);



        ((OA2SE) getServiceEnvironment()).getAdminClientStore().save(client);
        info("Adding approval record for client=" + client.getIdentifierString());
        ClientApproval clientApproval = new ClientApproval(client.getIdentifier());
        clientApproval.setApproved(false);

        info("done with client registration, client=" + client.getIdentifierString());
        return client;
    }

    @Override
    protected void save(BaseClient client) {
        ((OA2SE)getServiceEnvironment()).getAdminClientStore().save((AdminClient)client);
    }
}
