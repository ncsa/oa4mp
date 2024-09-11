package org.oa4mp.server.loader.oauth2.servlet;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.claims.AbstractPayloadConfig;
import org.oa4mp.server.loader.oauth2.loader.OA2ConfigurationLoader;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;
import org.oa4mp.server.api.storage.servlet.MyProxyDelegationServlet;
import org.oa4mp.delegation.common.servlet.TransactionState;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpStatus;
import org.oa4mp.delegation.server.*;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.StringTokenizer;

import static org.oa4mp.server.api.storage.servlet.MyProxyDelegationServlet.getServiceEnvironment;
import static org.oa4mp.delegation.server.OA2Constants.SCOPE;

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
    public static long computeATLifetime(OA2ServiceTransaction st2, OA2Client client, OA2SE oa2SE) {
        if (oa2SE.getMaxATLifetime() <= 0) {
            throw new NFWException("the server-wide default for the access token lifetime has not been set.");
        }
        return computeTokenLifetime(oa2SE.getMaxATLifetime(),
                oa2SE.getAccessTokenLifetime(),
                //OA2ConfigurationLoader.ACCESS_TOKEN_LIFETIME_DEFAULT,
                client.getAtLifetime(),
                client.getMaxATLifetime(),
                client.getAccessTokensConfig(),
                st2.getRequestedATLifetime());
    }

    public static long computeATLifetime(OA2ServiceTransaction st2, OA2SE oa2SE) {
        return computeATLifetime(st2, st2.getOA2Client(), oa2SE);
    }

    /**
     * The contract for this:
     * <ol>
     *     <li>Figure out the max lifetime. Any result is less than or equal to this</li>
     *     <li>If configured client lifetime =-1, return the server default </li>
     *     <li>Determine what the lifetime is. The order is client lifetime, script lifetime, requested lifetime</li>
     * </ol>
     *
     * This is the single point where all lifetime logic is handled.
     * @param serverMaxLifetime
     * @param defaultServerLifetime
     * @param clientLifetime
     * @param clientMaxLifetime
     * @param config
     * @param requestLifetime
     * @return
     */
    public static long computeTokenLifetime(long serverMaxLifetime,
                                               long defaultServerLifetime,
                                               long clientLifetime,
                                               long clientMaxLifetime,
                                               AbstractPayloadConfig config,
                                               long requestLifetime) {
        return computeTokenLifetime(serverMaxLifetime,
                defaultServerLifetime,
                clientLifetime,
                clientMaxLifetime,
                config == null ? null : config.getLifetime(),
                requestLifetime);
        // If the server default is <= 0 that implies there is some misconfiguration. Better to find that out here than
        // get squirrelly results later.
/*
        if (serverMaxLifetime <= 0) {
            throw new NFWException("the server-wide default for the token lifetime has not been set.");
        }
        long maxLifetime = serverMaxLifetime;
        if (0 < clientMaxLifetime) {
            maxLifetime = Math.min(clientMaxLifetime, serverMaxLifetime);
        }
//        OA2Client client = (OA2Client) st2.getClient();
        long lifetime = -1L;
        if (0 < clientLifetime) {
            lifetime = Math.min(clientLifetime, maxLifetime);
        } else {
            // client lifetime <= 0
            lifetime = defaultServerLifetime;
        }

        if (config != null) {
            if (0 < config.getLifetime()) {
                lifetime = Math.min(config.getLifetime(), maxLifetime);
            }
        }

        // If the transaction has a specific request, take it in to account.
        if (0 < requestLifetime) {
            // IF they specified an  access token lifetime in the request, take the minimum of that
            // and whatever they client is allowed.
            lifetime = Math.min(requestLifetime, maxLifetime);
        }
        return lifetime;
*/

    }

    /**
     * Does all the actual computation for lifetimes. It is public thanks to Java package visibility
     * requirements, but generally should not be called directly.
     * @param serverMaxLifetime
     * @param defaultServerLifetime
     * @param clientLifetime
     * @param clientMaxLifetime
     * @param clientConfiguredLifetime
     * @param requestLifetime
     * @return
     */
    public static long computeTokenLifetime(long serverMaxLifetime,
                                               long defaultServerLifetime,
                                               long clientLifetime,
                                               long clientMaxLifetime,
                                               Long clientConfiguredLifetime,
                                               long requestLifetime) {
        // If the server default is <= 0 that implies there is some misconfiguration. Better to find that out here than
        // get squirrelly results later.
        if (serverMaxLifetime <= 0) {
            throw new NFWException("the server-wide default for the token lifetime has not been set.");
        }
        long maxLifetime = serverMaxLifetime;
        if (0 < clientMaxLifetime) {
            maxLifetime = Math.min(clientMaxLifetime, serverMaxLifetime);
        }
//        OA2Client client = (OA2Client) st2.getClient();
        long lifetime = -1L;
        if (0 < clientLifetime) {
            lifetime = Math.min(clientLifetime, maxLifetime);
        } else {
            // client lifetime <= 0
            lifetime = defaultServerLifetime;
        }

        if (clientConfiguredLifetime != null) {
            if (0 < clientConfiguredLifetime) {
                lifetime = Math.min(clientConfiguredLifetime, maxLifetime);
            }
        }

        // If the transaction has a specific request, take it in to account.
        if (0 < requestLifetime) {
            // IF they specified an  access token lifetime in the request, take the minimum of that
            // and whatever they client is allowed.
            lifetime = Math.min(requestLifetime, maxLifetime);
        }
        return lifetime;

    }

    public static long computeRTGracePeriod(OA2Client client, OA2SE oa2SE) {
        if (!oa2SE.isRTGracePeriodEnabled()) {
            return 0L; // means no grace period.
        }
        if (client.getRtGracePeriod() == OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_USE_SERVER_DEFAULT) {
            return oa2SE.getRtGracePeriod();
        }
        return client.getRtGracePeriod();
    }

    public static long computeIDTLifetime(OA2ServiceTransaction st2, OA2SE oa2SE) {
        return computeIDTLifetime(st2, st2.getOA2Client(), oa2SE);
    }

    public static long computeIDTLifetime(OA2ServiceTransaction st2, OA2Client client, OA2SE oa2SE) {
        if (oa2SE.getMaxIdTokenLifetime() <= 0) {
            throw new NFWException("the server-wide default for the IDToken token lifetime has not been set.");
        }
        return computeTokenLifetime(oa2SE.getMaxIdTokenLifetime(),
                oa2SE.getIdTokenLifetime(),
                //OA2ConfigurationLoader.ID_TOKEN_LIFETIME_DEFAULT,
                client.getIdTokenLifetime(),
                client.getMaxIDTLifetime(),
                client.getIDTokenConfig(),
                st2.getRequestedIDTLifetime());
    }

    /**
     * For cases where you <b>know</b> that the client is not overridden.
     *
     * @param st2
     * @param oa2SE
     * @return
     */
    protected static long computeATLifetimeNEW(OA2ServiceTransaction st2, OA2SE oa2SE) {
        return computeATLifetime(st2, st2.getOA2Client(), oa2SE);
    }

    /**
     * The lifetime of the refresh token. This is the non-zero minimum of the client's requested
     * lifetime, the user's request at authorization time and the server global limit.
     *
     * @param st2
     * @return
     */
    public static long computeRefreshLifetime(OA2ServiceTransaction st2, OA2Client client, OA2SE oa2SE) {
        return computeRefreshLifetimeNEW(st2, client, oa2SE);
        //return computeRefreshLifetimeOLD(st2, oa2SE);
    }

    public static long computeRefreshLifetime(OA2ServiceTransaction st2, OA2SE oa2SE) {
        return computeRefreshLifetime(st2, st2.getOA2Client(), oa2SE);
    }

    public static long computeRefreshLifetimeOLD(OA2ServiceTransaction st2, OA2SE oa2SE) {
        //        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        if (!oa2SE.isRefreshTokenEnabled()) {
            throw new NFWException("Refresh tokens are disabled for this server.");
        }
        if (oa2SE.getMaxRTLifetime() <= 0) {
            throw new NFWException("Either refresh tokens are disabled for this server, or the server-wide default for the refresh token lifetime has not been set.");
        }
        long lifetime = -1L;

        OA2Client client = (OA2Client) st2.getClient();
        if (0 < client.getRtLifetime()) {
            lifetime = Math.min(oa2SE.getMaxRTLifetime(), client.getRtLifetime());
        } else {
            lifetime = OA2ConfigurationLoader.REFRESH_TOKEN_LIFETIME_DEFAULT;
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

    public static long computeRefreshLifetimeNEW(OA2ServiceTransaction st2, OA2Client client, OA2SE oa2SE) {
        if (!oa2SE.isRefreshTokenEnabled()) {
            throw new NFWException("Refresh tokens are disabled for this server.");
        }
        if (oa2SE.getMaxRTLifetime() <= 0) {
            throw new NFWException("Either refresh tokens are disabled for this server, or the server-wide default for the refresh token lifetime has not been set.");
        }

        return computeTokenLifetime(oa2SE.getMaxRTLifetime(),
                oa2SE.getRefreshTokenLifetime(),
                //OA2ConfigurationLoader.REFRESH_TOKEN_LIFETIME_DEFAULT,
                client.getRtLifetime(),
                client.getMaxRTLifetime(),
                client.getRefreshTokensConfig(),
                st2.getRequestedRTLifetime());
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
                        HttpStatus.SC_UNAUTHORIZED, null, client);
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
                throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT, "client has no configured secret", (String) null);
            } else {
                throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                        "client has no configured secret.",
                        HttpStatus.SC_UNAUTHORIZED, null, client);
            }
        }

        if (!client.getSecret().equals(DigestUtils.sha1Hex(rawSecret))) {
            debugger.trace(ClientUtils.class, "verifyClientSecret: bad secret, throwing exception.");
            if (isAT) {
                throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                        "incorrect secret", client);
            } else {
                throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                        "incorrect secret",
                        HttpStatus.SC_UNAUTHORIZED, null, client);
            }
        }
        debugger.trace(ClientUtils.class, "verifyClientSecret: secret ok.");

    }

    public static void verifyClient(OA2Client client, HttpServletRequest request, boolean isAT) {


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
        if (OA2HeaderUtils.hasBasicHeader(request)) {
            DebugUtil.trace(ClientUtils.class, "doIt: Got the header.");
            try {
                rawSecret = OA2HeaderUtils.getSecretFromHeaders(request);
            } catch (UnsupportedEncodingException e) {
                throw new NFWException("internal use of UTF-8 encoding failed");
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
    public static Collection<String> resolveScopes(TransactionState transactionState, OA2Client oa2Client, boolean isRFC8628) {
        return resolveScopes(transactionState, oa2Client, false, isRFC8628);
    }

    public static Collection<String> resolveScopes(OA2ServiceTransaction t) {
        return resolveScopes(null, t, t.getOA2Client(), false, false);
    }

    public static Collection<String> resolveScopes(HttpServletRequest request,
                                                   OA2ServiceTransaction st,
                                                   OA2Client oa2Client,
                                                   boolean isNew,
                                                   boolean isRFC8628) {
        String rawScopes = request.getParameter(SCOPE);
        Collection<String> passedInScopes = new ArrayList<>();
        StringTokenizer stringTokenizer = new StringTokenizer(rawScopes);
        while (stringTokenizer.hasMoreTokens()) {
            passedInScopes.add(stringTokenizer.nextToken());
        }
        return resolveScopes(request, st, oa2Client, passedInScopes, isNew, isRFC8628);
    }

    public static Collection<String> resolveScopes(HttpServletRequest request,
                                                   OA2ServiceTransaction st,
                                                   OA2Client oa2Client,
                                                   Collection passedInScopes,
                                                   boolean isNew,
                                                   boolean isRFC8628) {

        Collection<String> requestedScopes = new ArrayList<>();

        if (passedInScopes.isEmpty()) {
            // It is possible that there are no scopes set for this client at all, e.g.
            // a pure OAuth 2 client that only later will use scopes to exclusively
            // request access token scopes.
            return requestedScopes;
        }
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(st.getOA2Client());
        /*
        debugger.trace(ClientUtils.class, ".resolveScopes: stored client scopes =" + ((OA2Client) st.getClient()).getScopes());
        debugger.trace(ClientUtils.class, ".resolveScopes: passed in scopes =" + rawScopes);
        debugger.trace(ClientUtils.class, ".resolveScopes: Scope util =" + OA2Scopes.ScopeUtil.getScopes());
        debugger.trace(ClientUtils.class, ".resolveScopes: server scopes=" + ((OA2SE) getServiceEnvironment()).getScopes());
        debugger.trace(ClientUtils.class, ".resolveScopes: user validated scopes=" + st.getValidatedScopes());
        */

/*        if (isRFC8628) {
            // It is never an error to have no scopes if this is the RFC8628 servlet, since there is no way
            // to pass them in during the initial request. Just return an empty list
            return requestedScopes;
        } else {
            // It is possible that there are no scopes at all for a pure OAuth 2 client.
            if (!oa2Client.getScopes().isEmpty()) {
                throw new OA2RedirectableError(OA2Errors.INVALID_SCOPE,
                        "Missing scopes parameter.",
                        HttpStatus.SC_BAD_REQUEST,
                        st.getRequestState(),
                        st.getCallback(), oa2Client);
            }
        //    return requestedScopes;
        }*/
        // The scopes the client wants:

        // Fixes github issue 8, support for public clients: https://github.com/ncsa/oa4mp/issues/8
        if (oa2Client.isPublicClient()) {
            if (!oa2Client.getScopes().contains(OA2Scopes.SCOPE_OPENID)) {
                throw new OA2RedirectableError(OA2Errors.INVALID_REQUEST,
                        "The " + OA2Scopes.SCOPE_OPENID + " scope is missing from the request.",
                        HttpStatus.SC_BAD_REQUEST,
                        st.getRequestState(),
                        st.getCallback(), oa2Client);
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

        //StringTokenizer stringTokenizer = new StringTokenizer(rawScopes);
        boolean hasOpenIDScope = false;
        for (Object y : passedInScopes) {
            String x = y.toString();
            // CIL-1012 offline_access. Some clients end this along, but it has no effect.
            // Basically if get it, we don't want to throw an error.
            if (x.equals(OA2Scopes.SCOPE_OFFLINE_ACCESS)) {
                // Basically just always ignore it.
                continue;
            }
            // CIL-1732 Policy clarification. Strict means either in the approved server list or in the configured client list.
            if (oa2Client.useStrictScopes() && !OA2Scopes.ScopeUtil.hasScope(x) && !oa2Client.getScopes().contains(x)) {
                throw new OA2RedirectableError(OA2Errors.INVALID_SCOPE,
                        "Unrecognized scope \"" + x + "\"",
                        HttpStatus.SC_BAD_REQUEST,
                        st.getRequestState(),
                        st.getCallback(), oa2Client);
            }
            if (x.equals(OA2Scopes.SCOPE_OPENID)) hasOpenIDScope = true;
            requestedScopes.add(x);
        }
        if (((OA2SE) getServiceEnvironment()).isOIDCEnabled()) {

            if (oa2Client.getScopes().contains(OA2Scopes.SCOPE_OPENID) && !hasOpenIDScope)
                throw new OA2RedirectableError(OA2Errors.INVALID_REQUEST,
                        "The " + OA2Scopes.SCOPE_OPENID + " scope is missing from the request.",
                        HttpStatus.SC_BAD_REQUEST,
                        st.getRequestState(),
                        st.getCallback(), oa2Client);
        }
        st.setScopes(requestedScopes);

        debugger.trace(ClientUtils.class, ".resolveScopes: " + (oa2Client.useStrictScopes() ? "" : "non-") + "strict scopes after resolution=" + requestedScopes);
        return requestedScopes;

    }

    public static Collection<String> resolveScopes(TransactionState transactionState, OA2Client oa2Client, boolean isNew, boolean isRFC8628) {
        // Next 2 parameters are so error messages can be reasonably constructed, naught else
        return resolveScopes(transactionState.getRequest(), (OA2ServiceTransaction) transactionState.getTransaction(), oa2Client, isNew, isRFC8628);
    }


}
