package org.oa4mp.server.loader.oauth2.servlet;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.api.storage.servlet.AbstractRegistrationServlet;
import org.oa4mp.server.api.util.NewClientEvent;
import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.server.OA2Scopes;
import org.oa4mp.delegation.server.server.config.LDAPConfiguration;
import org.oa4mp.delegation.server.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.core.exceptions.RetryException;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.servlet.PresentableState;
import edu.uiuc.ncsa.security.util.crypto.KeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
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
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

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

    protected Collection<String> getDisplayScopes() {
        Collection<String> displayScopes = new HashSet<>();
/*        for (String x : OA2Scopes.basicScopes) {
            displayScopes.add(x);
        }*/
        displayScopes.addAll(getOA2SE().getScopes());
        if (!displayScopes.contains(OA2Scopes.SCOPE_OFFLINE_ACCESS)) {
            displayScopes.add(OA2Scopes.SCOPE_OFFLINE_ACCESS);
        }
        TreeSet<String> d = new TreeSet<>();
        d.addAll(displayScopes);
        return d; // unique-fies them since we can get repeats
    }

    @Override
    public void prepare(PresentableState state) throws Throwable {
        super.prepare(state);
        HttpServletRequest request = state.getRequest();

        if (state.getState() == INITIAL_STATE) {
            Collection<String> displayScopes = getDisplayScopes();
            String[] scopes = new String[displayScopes.size()];
            displayScopes.toArray(scopes);
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
                LinkedList<String> publicScopes = new LinkedList<>();
                publicScopes.add(OA2Scopes.SCOPE_OPENID); // all that is allowed
                client.setScopes(publicScopes);
            } catch (Throwable t) {
                // do nothing. Then this is not a public client.
            }
        }

        if (client.isPublicClient()) {
            client.setSecret("(no secret)");
        } else {
            // https://github.com/ncsa/oa4mp/issues/111
            String publicKey = getParameter(request, CLIENT_PUBLIC_KEY);
            if (StringUtils.isTrivial(publicKey)) {
                // Now generate the client secret. We generate this here:
                byte[] bytes = new byte[getOA2SE().getClientSecretLength()];
                random.nextBytes(bytes);
                String secret64 = Base64.encodeBase64URLSafeString(bytes);
                // we have to return this to the client registration ok page and store a hash of it internally
                // so we don't have a copy of it any place but the client.
                // After this is displayed the secret is actually hashed and stored.
                client.setSecret(secret64);
            } else {
                client.setSecret("(no secret)");
                JSONWebKeys jsonWebKeys;
                boolean gotKey = false;
                try {
                    PublicKey publicKey1 = KeyUtil.fromX509PEM(publicKey);
                    // create the key
                    JSONWebKey jsonWebKey = new JSONWebKey();
                    jsonWebKey.publicKey = publicKey1;
                    Random random = new Random();
                    byte[] bytes = new byte[8];
                    random.nextBytes(bytes);
                    if (publicKey1 instanceof RSAPublicKey) {
                        jsonWebKey.type = "RSA";
                    } else {
                        throw new ClientRegistrationRetryException("The public key is not a supported type. Only RSA keys are supported.", null, client);
                    }
                    jsonWebKey.id = Base64.encodeBase64URLSafeString(bytes);
                    jsonWebKey.use = "sig";
                    jsonWebKey.algorithm = "RS256";
                    jsonWebKeys = new JSONWebKeys(jsonWebKey.id);
                    jsonWebKeys.put(jsonWebKey);
                    gotKey = true;
                } catch (Throwable t) {
                    try {
                        publicKey = publicKey.replace("\n", " "); // deserializer chokes on returns
                        publicKey = publicKey.replace("\r", " "); // deserializer chokes on returns
                        jsonWebKeys = JSONWebKeyUtil.fromJSON(publicKey);
                    } catch (Throwable tt) {
                        throw new ClientRegistrationRetryException("The public key could not be parsed as PKCS or JWK.", null, client);
                    }
                }
                client.setJWKS(jsonWebKeys);
            }
        }

        LinkedList<String> uris = OA2ClientUtils.createCallbacksForWebUI(client, rawCBs);
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


    protected Client addNewClient(HttpServletRequest request, HttpServletResponse response, boolean fireClientEvents) throws Throwable {
        OA2Client client = (OA2Client) setupNewClient(request, response);

        if (fireClientEvents) {
            fireNewClientEvent(new NewClientEvent(this, client));
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
                save(cState.getClient());
                //getServiceEnvironment().getClientStore().save(cState.getClient());
            } else {
                throw new IllegalStateException("An instance of ClientState was expected, but got an instance of \"" + state.getClass().getName() + "\"");
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
