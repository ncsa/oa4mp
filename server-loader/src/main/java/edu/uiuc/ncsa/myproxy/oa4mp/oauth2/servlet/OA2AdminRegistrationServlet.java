package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractRegistrationServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.NewAdminClientEvent;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.BaseClient;
import edu.uiuc.ncsa.security.servlet.PresentableState;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2RegistrationServlet.random;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/9/19 at  1:39 PM
 */
public class OA2AdminRegistrationServlet extends AbstractRegistrationServlet {
    public static final String ISSUER_NAME = "issuer";
    @Override
    protected String getInitPage() {
        return "admin-client-registration-init.jsp";
    }

    @Override
    protected String getOKPage() {
        return "admin-client-registration-ok.jsp";
    }


    protected BaseClient setupNewClient(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        OA2SE oa2se = (OA2SE) getServiceEnvironment();
        // Assumption is that the request is in good order and we just have to pull stuff off it.

        AdminClient client = oa2se.getAdminClientStore().create();
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
        // https://github.com/rcauth-eu/OA4MP/commit/5e1f937d412c1e336598f47f8a072743fe0d4115
        String issuer = getParameter(request, ISSUER_NAME);
              if (!isEmpty(issuer)) {
                  client.setIssuer(issuer);
              }
        byte[] bytes = new byte[oa2se.getClientSecretLength()];
        random.nextBytes(bytes);
        String secret64 = Base64.encodeBase64URLSafeString(bytes);
        // we have to return this to the client registration ok page and store a hash of it internally
        // so we don't have a copy of it any place but the client.
        // After this is displayed the secret is actually hashed and stored.
        client.setSecret(secret64);

        ((OA2SE) getServiceEnvironment()).getAdminClientStore().save(client);
        info("Adding approval record for client=" + client.getIdentifierString());
        ClientApproval clientApproval = new ClientApproval(client.getIdentifier());
        clientApproval.setApproved(false);

        info("done with client registration, client=" + client.getIdentifierString());
        return client;
    }

    @Override
    protected BaseClient addNewClient(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        AdminClient client = (AdminClient) setupNewClient(request, response);
        fireNewClientEvent(new NewAdminClientEvent(this, client));
        return client;
    }

    @Override
    protected void save(BaseClient client) {
        ((OA2SE) getServiceEnvironment()).getAdminClientStore().save((AdminClient) client);
    }

    @Override
    public void present(PresentableState state) throws Throwable {
        super.present(state);

        // after all is done, do not store the secret in the database, just a hash of it.
        if (state.getState() == REQUEST_STATE) {
            if (state instanceof ClientState) {
                // we should not store the client secret in the database, just a hash of it.
                ClientState cState = (ClientState) state;
                String secret = DigestUtils.sha1Hex(cState.getClient().getSecret());
                cState.getClient().setSecret(secret);
                save(cState.getClient());
                //getServiceEnvironment().getClientStore().save(cState.getClient());
            } else {
                throw new IllegalStateException("Error: An instance of ClientState was expected, but got an instance of \"" + state.getClass().getName() + "\"");
            }

        }
    }

    @Override
        public void prepare(PresentableState state) throws Throwable {
            super.prepare(state);
            HttpServletRequest request = state.getRequest();

            if (state.getState() == INITIAL_STATE) {
                request.setAttribute(ISSUER_NAME, ISSUER_NAME);
            }
        }
}
