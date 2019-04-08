package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractRegistrationServlet;
import edu.uiuc.ncsa.security.core.exceptions.RetryException;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.servlet.PresentableState;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import net.sf.json.JSON;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.LinkedList;
import java.util.StringTokenizer;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/20/14 at  4:48 PM
 */
public class OA2RegistrationServlet extends AbstractRegistrationServlet {

    protected static SecureRandom random = new SecureRandom();
    public static final String CALLBACK_URI = "callbackURI";
    public static final String REFRESH_TOKEN_LIFETIME = "rtLifetime";
    public static final String REFRESH_TOKEN_FIELD_VISIBLE = "rtFieldVisible";
    public static final String VO_NAME = "voName";
    public static final String LDAP_NAME = "ldap";
    public static final String ISSUER_NAME = "issuer";
    public static final String SCOPES_NAME = "scopes";

    protected OA2SE getOA2SE() {
        return (OA2SE) getServiceEnvironment();
    }

    @Override
    public void prepare(PresentableState state) throws Throwable {
        super.prepare(state);
        HttpServletRequest request = state.getRequest();

        if (state.getState() == INITIAL_STATE) {
            String[] scopes = new String[getOA2SE().getScopes().size()];
            getOA2SE().getScopes().toArray(scopes);
            request.setAttribute(SCOPES_NAME, scopes);
            request.setAttribute(VO_NAME, VO_NAME);
            request.setAttribute(LDAP_NAME, LDAP_NAME);
            request.setAttribute(ISSUER_NAME, ISSUER_NAME);
            request.setAttribute(CALLBACK_URI, CALLBACK_URI);
            //request.setAttribute(getValueTag(CLIENT_CALLBACK_URI), "Put your callbacks here, one per line.");
            request.setAttribute(REFRESH_TOKEN_LIFETIME, REFRESH_TOKEN_LIFETIME);
            if (getOA2SE().isRefreshTokenEnabled()) {
                request.setAttribute(REFRESH_TOKEN_FIELD_VISIBLE, " ");  // it's visible
            } else {
                request.setAttribute(REFRESH_TOKEN_FIELD_VISIBLE, " style=\"display: none;\""); // it's not
            }
        }
    }

    protected Client setupNewClient(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        OA2Client client = (OA2Client) super.setupNewClient(request, response);
        String rawCBs = getRequiredParam(request, CALLBACK_URI, client);
        String rawRTLifetime = getParameter(request, REFRESH_TOKEN_LIFETIME);
        String[] rawScopes = request.getParameterValues("chkScopes");
        if (rawScopes != null) {
            Collection<String> newScopes = new LinkedList<>();
            boolean hasDefaultScope = false;
            for (String scope : rawScopes) {
                if (OA2Scopes.SCOPE_OPENID.equals(scope)) hasDefaultScope = true;
                newScopes.add(scope);
            }
            if (!hasDefaultScope) {
                newScopes.add(OA2Scopes.SCOPE_OPENID); // has to be there or all requests are rejected.
            }
            client.setScopes(newScopes);
        }
        String issuer = getParameter(request, ISSUER_NAME);
        String ldap = getParameter(request, LDAP_NAME);
        if (!isEmpty(issuer)) {
            client.setIssuer(issuer);
        }
        if (!isEmpty(ldap)) {
            try {
                JSON json = JSONObject.fromObject(ldap);
                LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();

                Collection<LDAPConfiguration> ldapConfiguration = ldapConfigurationUtil.fromJSON(json);
                client.setLdaps(ldapConfiguration);
            } catch (Throwable t) {
                warn("Could not parse LDAP string during client registration for \"" + client.getIdentifierString() + "\". Skipping...");
            }
        }
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
        String rawIsPublic = getParameter(request, CLIENT_IS_PUBLIC);
        client.setPublicClient(false); // default

        if (rawIsPublic != null) {
            try {
                client.setPublicClient(rawIsPublic.equals("on"));
            } catch (Throwable t) {
                // do nothing. Then this is not a public client.
            }
        }

        if (client.isPublicClient()) {
            client.setSecret("(no secret)");
        } else {
            // Now generate the client secret. We generate this here:
            byte[] bytes = new byte[getOA2SE().getClientSecretLength()];
            random.nextBytes(bytes);
            String secret64 = Base64.encodeBase64URLSafeString(bytes);
            // we have to return this to the client registration ok page and store a hash of it internally
            // so we don't have a copy of it any place but the client.
            // After this is displayed the secret is actually hashed and stored.
            client.setSecret(secret64);
        }

        LinkedList<String> uris = createCallbacks(client, rawCBs);
        //LinkedList<String> uris = newCreateCallbacks(rawCBs);
        client.setCallbackURIs(uris);
        client.setSignTokens(true); // part of CIL-359, signing ID tokens.
        // CIL-414 makes the approval record here so that we can get an accurate count later.
        ClientApproval approval = (ClientApproval) getOA2SE().getClientApprovalStore().create();
        approval.setApproved(false);
        approval.setIdentifier(client.getIdentifier());
        getOA2SE().getClientApprovalStore().save(approval);
        return client;
    }

    private LinkedList<String> newCreateCallbacks(String rawCBs) throws IOException {
        BufferedReader br = new BufferedReader(new StringReader(rawCBs));
        String x = br.readLine();
        LinkedList<String> uris = new LinkedList<>();
        while (x != null) {
            try {
                URI.create(x);// just use this to check for URI syntax. No other checking.
                uris.add(x);
            } catch (Throwable t) {
            }
            x = br.readLine();
        }
        return uris;
    }

    private LinkedList<String> createCallbacks(OA2Client client, String rawCBs) throws IOException {
        BufferedReader br = new BufferedReader(new StringReader(rawCBs));
        String x = br.readLine();
        LinkedList<String> uris = new LinkedList<>();
        LinkedList<String> dudUris = new LinkedList<>();
        while (x != null) {
            // Fix for CIL-545. Allowing a wider range of redirect URIs to support devices such as smart phones.
            // How it works: Either the protocol is not http/https in which case it is allowed
            // but if it is http, only localhost is permitted. Any https works.
            try {
                URI temp = URI.create(x);
                String host = temp.getHost();
                String scheme = temp.getScheme();
                ServletDebugUtil.trace(this.getClass(), "setupNewClient, processing callback \"" + x + "\"");

                if (scheme != null && scheme.toLowerCase().equals("https")) {
                    // any https works
                    uris.add(x);
                } else {
                    if (isPrivate(host, scheme)) {
                        uris.add(x);
                    } else {
                        if (temp.getAuthority() == null || temp.getAuthority().isEmpty()) {
                            /*
                            Finally, if it does not have an authority, then it is probably
                            an intention for another (probably mobile) device (so in that case,
                            the browser on the device has the table associating schemes with
                            specific applications. When it sees a uri with this scheme, it
                            invokes the associated application and hands it the URI. This allows
                            the browser to do a redirect to an application. The requirement is that there is a scheme, but
                            there is no authority:
                             E.g. https://bob@foo.com/blah/woof
                             has authority of "//bob@foo.com/"

                             An example of what this block allows (or should) is a uri like

                             com.example.app:/oauth2redirect/example-provider

                             which has a scheme, no authority and a path.
                             */
                            uris.add(x);
                        } else {
                            dudUris.add(x);
                        }
                    }
                }

            } catch (IllegalArgumentException urisx) {
                dudUris.add(x);
            }

        /*  Old stuff before CIL-545
           if (!x.toLowerCase().startsWith("https:")) {
                warn("Attempt to add bad callback uri for client " + client.getIdentifierString());
                throw new ClientRegistrationRetryException("The callback \"" + x + "\" is not secure.", null, client);
            }
            URI.create(x); // passes here means it is a uri. All we want this to do is throw an exception if needed.

            uris.add(x);*/
            x = br.readLine();
        }
        if (0 < dudUris.size()) {
            String xx = "</br>";
            boolean isOne = dudUris.size() == 1;
            for (String y : dudUris) {
                xx = xx + y + "</br>";
            }
            warn("Attempt to add bad callback uris for client " + client.getIdentifierString());
            String helpfulMessage = "The callback" + (isOne ? " " : "s ") + xx + (isOne ? "is" : "are") + " not valid.";
            throw new ClientRegistrationRetryException(helpfulMessage, null, client);

        }
        br.close();
        return uris;
    }

    protected int[] toQuad(String address) {
        StringTokenizer stringTokenizer = new StringTokenizer(address, ".");
        if (!stringTokenizer.hasMoreTokens()) {
            return null;
        }
        int[] quad = new int[4];

        for (int i = 0; i < 4; i++) {
            if (!stringTokenizer.hasMoreTokens()) {
                return null;
            }
            String raw = stringTokenizer.nextToken();
            try {
                quad[i] = Integer.parseInt(raw);
                if (!(0 <= quad[i] && quad[i] <= 255)) {
                    return null;
                }
            } catch (NumberFormatException nfx) {
                return null;
            }
        }
        if (stringTokenizer.hasMoreTokens()) {
            return null;
        }
        return quad;

    }

    protected boolean isOnPrivateNetwork(String address) {
        String regex = "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b";
        if (!address.matches(regex)) {
            return false;
        }
        int[] quad = toQuad(address);
        if (quad == null) {
            return false;
        }
        if (quad[0] == 10) {
            return true;
        }
        if (quad[0] == 192 && quad[1] == 168) return true;
        if (quad[0] == 172 && (16 <= quad[1] && quad[1] <= 31)) return true;
        if (quad[0] == 127 && quad[1] == 0 && quad[2] == 0 && quad[3] == 1) return true;

        // This just checked that it is a dotted quad address. We could have used InetAddress which
        // only checks a valid dotted quad for format, **but** might also do an actual address lookup
        // if there is a question, so that really doesn't help.

        // now we have to check that address in the range 172.16.x.x to 172.31.x.x are included.
        // Do the easy ones first.
        return false;
    }

    protected boolean isPrivate(String host, String scheme) {
        if (host != null && isOnPrivateNetwork(host)) {
            // scheme does not matter in this case since it is a private network.
            // note that this also catches the loopback address of 127.0.0.1 
            return true;
        }
        if (scheme != null && scheme.toLowerCase().equals("http")) {
            // only localhost works for http
            if (host.toLowerCase().equals("localhost") ||
                    host.equals("[::1]")) {
                return true;
            }
        }


        return false;
    }

    protected Client addNewClient(HttpServletRequest request, HttpServletResponse response, boolean fireClientEvents) throws Throwable {
        OA2Client client = (OA2Client) setupNewClient(request, response);

        if (fireClientEvents) {
            fireNewClientEvent(client);
        }
        return client;
    }

    @Override
    protected Client addNewClient(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        return addNewClient(request, response, true);
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
                String secret = DigestUtils.sha1Hex(cState.getClient().getSecret());
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
        // reset the scopes or they won't display.
        // Partial fix for CIL-498 This won't pick up on
        String[] scopes = new String[getOA2SE().getScopes().size()];
        getOA2SE().getScopes().toArray(scopes);
        request.setAttribute(SCOPES_NAME, scopes);
    }
}
