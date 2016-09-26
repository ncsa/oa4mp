package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractRegistrationServlet;
import edu.uiuc.ncsa.security.core.exceptions.RetryException;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.servlet.PresentableState;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.StringReader;
import java.net.URI;
import java.security.SecureRandom;
import java.util.LinkedList;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/20/14 at  4:48 PM
 */
public class OA2RegistrationServlet extends AbstractRegistrationServlet {

    protected static SecureRandom random = new SecureRandom();
    public static final String CALLBACK_URI = "callbackURI";
    public static final String REFRESH_TOKEN_LIFETIME = "rtLifetime";
    public static final String REFRESH_TOKEN_FIELD_VISIBLE = "rtFieldVisible";

    protected OA2SE getOA2SE() {
        return (OA2SE) getServiceEnvironment();
    }

    @Override
    public void prepare(PresentableState state) throws Throwable {
        super.prepare(state);
        HttpServletRequest request = state.getRequest();

        if (state.getState() == INITIAL_STATE) {
            request.setAttribute(CALLBACK_URI, CALLBACK_URI);
            request.setAttribute(getValueTag(CLIENT_CALLBACK_URI), "Put your callbacks here, one per line.");
            request.setAttribute(REFRESH_TOKEN_LIFETIME, REFRESH_TOKEN_LIFETIME);
            if (getOA2SE().isRefreshTokenEnabled()) {
                request.setAttribute(REFRESH_TOKEN_FIELD_VISIBLE, " ");  // it's visible
            } else {
                request.setAttribute(REFRESH_TOKEN_FIELD_VISIBLE, " style=\"display: none;\""); // it's not
            }
        }
    }

    @Override
    protected Client addNewClient(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        OA2Client client = (OA2Client) super.addNewClient(request, response);
        String rawCBs = getRequiredParam(request, CALLBACK_URI, client);
        String rawRTLifetime = getParameter(request, REFRESH_TOKEN_LIFETIME);
        try {
            URI.create(client.getHomeUri());
        } catch (Throwable t) {
            throw new ClientRegistrationRetryException("Error. The stated home uri is invalid: " + t.getMessage(), null, client);
        }
        if (rawRTLifetime == null || rawRTLifetime.length() == 0) {
            // This effectively means there is no refresh token set.
            client.setRtLifetime(0); // FIXES CIL-309 (partial)
        } else {
            long clientRtLifetime = 0L;
            boolean rtLifetimeOK = true;
            if (rawRTLifetime != null && 0 < rawRTLifetime.length()) {
                try {
                    clientRtLifetime = Long.parseLong(rawRTLifetime) * 1000; // The value is in seconds on the form
                    if (clientRtLifetime < 0) {
                        rtLifetimeOK = false;
                    } else {
                        rtLifetimeOK = true;
                    }
                } catch (Throwable t) {
                    // do nix...
                    rtLifetimeOK = false;
                }
                if (!rtLifetimeOK) {
                    info("Client requested illegal value for refresh token lifetime at registration of \"" + rawRTLifetime + "\"");
                }
            }
            client.setRtLifetime(Math.min(getOA2SE().getMaxClientRefreshTokenLifetime(), clientRtLifetime)); // FIX CIL-309 (partial)
        }
        // Now generate the client secret. We generate this here:
        byte[] bytes = new byte[getOA2SE().getClientSecretLength()];
        random.nextBytes(bytes);
        String secret64 = Base64.encodeBase64URLSafeString(bytes);
        // we have to return this to the client registration ok page and store a hash of it internally
        // so we don't have a copy of it any place but the client.
        // After this is displayed the secret is actually hashed and stored.
        client.setSecret(secret64);
        BufferedReader br = new BufferedReader(new StringReader(rawCBs));
        String x = br.readLine();
        LinkedList<String> uris = new LinkedList<>();
        while (x != null) {
            if (!x.toLowerCase().startsWith("https:")) {
                warn("Attempt to add bad callback uri for client " + client.getIdentifierString());
                throw new ClientRegistrationRetryException("The callback \"" + x + "\" is not secure.", null, client);
            }
            URI.create(x); // passes here means it is a uri. All we want this to do is throw an exception if needed.

            uris.add(x);
            // skip it.
            x = br.readLine();
        }
        br.close();
        client.setCallbackURIs(uris);
        fireNewClientEvent(client);
        return client;
    }

    /**
     * We override this to set the client secret to be displayed at registration time.
     *
     * @param state
     * @throws Throwable
     */
    @Override
    public void present(PresentableState state) throws Throwable {
        super.present(state);

        // after all is done, do not store the secret in the database, just a hash of it.
        if (state.getState() == REQUEST_STATE) {
            if (state instanceof ClientState) {
                // we should not store the client secret in the database, just a hash of it.
                ClientState cState = (ClientState) state;
                String secret = DigestUtils.shaHex(cState.getClient().getSecret());
                cState.getClient().setSecret(secret);
                getServiceEnvironment().getClientStore().save(cState.getClient());
            } else {
                throw new IllegalStateException("Error: An instance of ClientState was expected, but got an instance of \"" + state.getClass().getName() + "\"");
            }

        }
    }

    @Override
    protected void setRetryParameters(HttpServletRequest request, RetryException r) {
        super.setRetryParameters(request, r);
        if (getOA2SE().isRefreshTokenEnabled()) {
            request.setAttribute(REFRESH_TOKEN_FIELD_VISIBLE, " ");  // it's visible
        } else {
            request.setAttribute(REFRESH_TOKEN_FIELD_VISIBLE, " style=\"display: none;\""); // it's not
        }
    }
}
