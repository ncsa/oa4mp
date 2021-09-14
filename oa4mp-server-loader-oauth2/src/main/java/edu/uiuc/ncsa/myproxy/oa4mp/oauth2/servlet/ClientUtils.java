package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.StringTokenizer;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizedServletUtil.intersection;
import static edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet.getServiceEnvironment;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.SCOPE;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/9/21 at  3:09 PM
 */
public class ClientUtils {
    /**
     * Scorecard:
     * <pre>
     *              server default | oa2SE.getAccessTokenLifetime()
     *          server default max | oa2SE.getMaxATLifetime();
     *          client default max | client.getAtLifetime()
     * value in cfg access element | client.getAccessTokensConfig().getLifetime()
     *        value in the request | st2.getRequestedATLifetime()
     *     actual definitive value | st2.getAccessTokenLifetime()
     *                      result | actual definitive value
     * </pre>
     * <p>
     * Policies: no lifetime can exceed the non-zero max of the server and client defaults. These are hard
     * limits placed there by administrators.
     * <p>
     * Note that inside of scripts, these can be reset to anything, so
     * <p>
     * st2.getAtData()
     * <p>
     * has the final, definitive values. Once this has been set in the first pass, it
     * **must** be authoritative.
     *
     * @param st2
     * @return
     */
    /*
    List of useful numbers for testing. These are all prime and are either in seconds or milliseconds as
    needed. Setting these in the configurations will let you track exactly what values are used.
    server default 97
     */
    public static long computeATLifetime(OA2ServiceTransaction st2, OA2SE oa2SE) {
//        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        // If the server default is <= 0 that implies there is some misconfiguration. Better to find that out here than
        // get squirrelly results later.
        if (oa2SE.getMaxATLifetime() <= 0) {
            throw new NFWException("Internal error: the server-wide default for the access token lifetime has not been set.");
        }
        long lifetime = oa2SE.getMaxATLifetime();
        st2.setMaxATLifetime(lifetime); // absolute max allowed on this server for this request

        OA2Client client = (OA2Client) st2.getClient();
        if (0 < client.getAtLifetime()) {
            lifetime = Math.min(client.getAtLifetime(), lifetime);
        } else {
            lifetime = Math.min(lifetime, OA2ConfigurationLoader.ACCESS_TOKEN_LIFETIME_DEFAULT);
        }

        if (client.hasAccessTokenConfig()) {
            if (0 < client.getAccessTokensConfig().getLifetime()) {
                lifetime = Math.min(client.getAccessTokensConfig().getLifetime(), lifetime);
            }
        }

        // If the transaction has a specific request, take it in to account.
        if (0 < st2.getRequestedATLifetime()) {
            // IF they specified a refresh token lifetime in the request, take the minimum of that
            // and whatever they client is allowed.
            lifetime = Math.min(st2.getRequestedATLifetime(), lifetime);
        }
        return lifetime;

    }

    /**
     * The lifetime of the refresh token. This is the non-zero minimum of the client's requested
     * lifetime, the user's request at authorization time and the server global limit.
     *
     * @param st2
     * @return
     */
    public static long computeRefreshLifetime(OA2ServiceTransaction st2, OA2SE oa2SE) {
//        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        if (!oa2SE.isRefreshTokenEnabled()) {
            throw new NFWException("Internal error: Refresh tokens are disabled for this server.");
        }
        if (oa2SE.getMaxRTLifetime() <= 0) {
            throw new NFWException("Internal error: Either refresh tokens are disabled for this server, or the server-wide default for the refresh token lifetime has not been set.");
        }
        long lifetime = oa2SE.getMaxRTLifetime();

        OA2Client client = (OA2Client) st2.getClient();
        if (0 < client.getRtLifetime()) {
            lifetime = Math.min(lifetime, client.getRtLifetime());
        }
        st2.setMaxRTLifetime(lifetime);// absolute max allowed on this server for this request


        if (client.hasRefreshTokenConfig()) {
            if (0 < client.getRefreshTokensConfig().getLifetime()) {
                lifetime = Math.min(client.getRefreshTokensConfig().getLifetime(), lifetime);
            }
        }
        if (0 < st2.getRequestedRTLifetime()) {
            // IF they specified a refresh token lifetime in the request, take the minimum of that
            // and whatever they client is allowed.
            lifetime = Math.min(st2.getRequestedRTLifetime(), lifetime);
        }

        return lifetime;
    }

    /**
     * This verifies secrets only call if the client has a secret (e.g. do not call this
     * if the client is public). This is because it will do various checks in the assumption
     * that the client <b>must</b> have a secret and raise errors if it is missing, etc.
     *
     * @param client
     * @param rawSecret
     * @param isAT
     */
    public static void verifyClientSecret(OA2Client client, String rawSecret, boolean isAT) {
        // Fix for CIL-332
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(client);
        if (rawSecret == null) {
            debugger.trace(ClientUtils.class, "verifyClientSecret: no secret, throwing exception.");
            if (isAT) {
                throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT, "missing secret");
            } else {
                throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                        "missing secret",
                        HttpStatus.SC_UNAUTHORIZED, null);
            }
        }
        if (StringUtils.isTrivial(client.getSecret())) {
            debugger.trace(ClientUtils.class, "verifyClientSecret: no secret, so client is not configured right.");
            // Since clients can be administered by others now, we are finding that they sometimes
            // may change their scopes. If a client is public, there is no secret, but if
            // a client later is updated to have different scopes, then trying to use it for other
            // purposes gets an NPE here. Tell them when they use their client next rather
            // than blowing up with an NPE.
            if (isAT) {
                throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT, "client has no configured secret", null);
            } else {
                throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                        "client has no configured secret.",
                        HttpStatus.SC_UNAUTHORIZED, null);
            }
        }

        if (!client.getSecret().equals(DigestUtils.sha1Hex(rawSecret))) {
            debugger.trace(ClientUtils.class, "verifyClientSecret: bad secret, throwing exception.");
            if (isAT) {
                throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                        "incorrect secret");
            } else {
                throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                        "incorrect secret",
                        HttpStatus.SC_UNAUTHORIZED, null);
            }
        }
        debugger.trace(ClientUtils.class, "verifyClientSecret: secret ok.");

    }

    /**
     * This either peels the secret off the parameter list if it is there or from the headers. It
     * merely returns the raw string that is the secret. No checking against a client is done.
     * Also, a null is a perfectly acceptable return value if there is no secret, e.g. the client is public.
     *
     * @param request
     * @return
     */
    public static String getClientSecret(HttpServletRequest request, String raw) {
        String rawSecret = null;
        // Fix for CIL-430. Check the header and decode as needed.
        if (HeaderUtils.hasBasicHeader(request)) {
            DebugUtil.trace(ClientUtils.class, "doIt: Got the header.");
            try {
                rawSecret = HeaderUtils.getSecretFromHeaders(request);
            } catch (UnsupportedEncodingException e) {
                throw new NFWException("Error: internal use of UTF-8 encoding failed");
            }

        } else {
            DebugUtil.trace(ClientUtils.class, "doIt: no header for authentication, looking at parameters.");
            rawSecret = raw;

        }

        return rawSecret;
    }

    /**
     * This method will take the scopes that the client sends in its request and inspect the scopes that it is allowed
     * to request. The result will be a list of permitted scopes. This is also where omitting the openid scope
     * causes the request to be rejected.
     *
     * @param transactionState
     * @return
     */
    public static Collection<String> resolveScopes(TransactionState transactionState, boolean isRFC8628) {
        return resolveScopes(transactionState, false, isRFC8628);
    }

    public static Collection<String> resolveScopes(TransactionState transactionState, boolean isNew, boolean isRFC8628) {
        // Next 2 parameters are so error messages can be reasonably constructed, naught else
        String rawScopes = transactionState.getRequest().getParameter(SCOPE);

        OA2ServiceTransaction st = (OA2ServiceTransaction) transactionState.getTransaction();
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(st.getOA2Client());
        debugger.trace(ClientUtils.class, ".resolveScopes: stored client scopes =" + ((OA2Client) st.getClient()).getScopes());
        debugger.trace(ClientUtils.class, ".resolveScopes: passed in scopes =" + rawScopes);
        debugger.trace(ClientUtils.class, ".resolveScopes: Scope util =" + OA2Scopes.ScopeUtil.getScopes());
        debugger.trace(ClientUtils.class, ".resolveScopes: server scopes=" + ((OA2SE) getServiceEnvironment()).getScopes());
        debugger.trace(ClientUtils.class, ".resolveScopes: user validated scopes=" + st.getValidatedScopes());
        if (rawScopes == null || rawScopes.length() == 0) {
            if (isRFC8628) {
                // It is not an error if this is the RFC8628 servlet. Just return an empty list
                return new ArrayList<>();
            } else {
                throw new OA2RedirectableError(OA2Errors.INVALID_SCOPE,
                        "Missing scopes parameter.",
                        HttpStatus.SC_BAD_REQUEST,
                        st.getRequestState(),
                        st.getCallback());
            }
        }
        // The scopes the client wants:
        OA2Client oa2Client = (OA2Client) st.getClient();
        Collection<String> requestedScopes = new ArrayList<>();

        // Fixes github issue 8, support for public clients: https://github.com/ncsa/OA4MP/issues/8
        if (oa2Client.isPublicClient()) {
            if (!oa2Client.getScopes().contains(OA2Scopes.SCOPE_OPENID)) {
                throw new OA2RedirectableError(OA2Errors.INVALID_REQUEST,
                        "The " + OA2Scopes.SCOPE_OPENID + " scope is missing from the request.",
                        HttpStatus.SC_BAD_REQUEST,
                        st.getRequestState(),
                        st.getCallback());
            }
            // only allowed scope, regardless of what is requested.
            // This also covers the case of a client made with a full set of scopes, then
            // converted to a public client but the stored scopes are not updated.
            requestedScopes.add(OA2Scopes.SCOPE_OPENID);
            debugger.trace(ClientUtils.class, ".resolveScopes: after resolution=" + requestedScopes);
            st.setScopes(requestedScopes); //Fix for CIL-936
            return requestedScopes;
        }
        // The scopes that minimally are allowed. Permissions scopes are never in this list.

        StringTokenizer stringTokenizer = new StringTokenizer(rawScopes);
        boolean hasOpenIDScope = false;
        while (stringTokenizer.hasMoreTokens()) {
            String x = stringTokenizer.nextToken();
            // CIL-1012 offline_access. Some clients end this along but it has no effect.
            // Basically if get it, we don't want to throw an error.
            if (x.equals(OA2Scopes.SCOPE_OFFLINE_ACCESS)) {
                // Basically just always ignore it.
                continue;
            }
            if (oa2Client.useStrictScopes() && !OA2Scopes.ScopeUtil.hasScope(x)) {
                throw new OA2RedirectableError(OA2Errors.INVALID_SCOPE,
                        "Unrecognized scope \"" + x + "\"",
                        HttpStatus.SC_BAD_REQUEST,
                        st.getRequestState(),
                        st.getCallback());
            }
            if (x.equals(OA2Scopes.SCOPE_OPENID)) hasOpenIDScope = true;
            requestedScopes.add(x);
        }
        if (((OA2SE) getServiceEnvironment()).isOIDCEnabled()) {

            if (!hasOpenIDScope)
                throw new OA2RedirectableError(OA2Errors.INVALID_REQUEST,
                        "The " + OA2Scopes.SCOPE_OPENID + " scope is missing from the request.",
                        HttpStatus.SC_BAD_REQUEST,
                        st.getRequestState(),
                        st.getCallback());
        }
        st.setScopes(requestedScopes);
        if (oa2Client.useStrictScopes()) {
            Collection<String> storedClientScopes = oa2Client.getScopes();
            requestedScopes = intersection(OA2Scopes.ScopeUtil.getScopes(), intersection(requestedScopes, storedClientScopes));
            debugger.trace(ClientUtils.class, ".resolveScopes: strict scopes after resolution=" + requestedScopes);
        } else {
            debugger.trace(ClientUtils.class, ".resolveScopes: non-strict scopes =" + requestedScopes);
        }
/*     Does not really work for access token scopes
       if(!isNew){
             requestedScopes = ScopeTemplateUtil.doCompareTemplates(st.getValidatedScopes(), requestedScopes, false);
         }*/
        return requestedScopes;
    }


}
