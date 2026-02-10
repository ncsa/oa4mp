package org.oa4mp.server.proxy;

import edu.uiuc.ncsa.security.core.exceptions.UnknownClientException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.configuration.TimeUtil;
import net.sf.json.JSONObject;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpStatus;
import org.oa4mp.delegation.common.servlet.TransactionState;
import org.oa4mp.delegation.common.token.impl.AuthorizationGrantImpl;
import org.oa4mp.delegation.common.token.impl.TokenUtils;
import org.oa4mp.delegation.server.*;
import org.oa4mp.delegation.server.request.AGResponse;
import org.oa4mp.delegation.server.request.IssuerResponse;
import org.oa4mp.delegation.server.server.AGRequest2;
import org.oa4mp.delegation.server.server.RFC7523Constants;
import org.oa4mp.delegation.server.server.RFC7636Util;
import org.oa4mp.delegation.server.server.RFC8628Constants;
import org.oa4mp.server.api.OA4MPConfigTags;
import org.oa4mp.server.api.storage.servlet.OA4MPServlet;
import org.oa4mp.server.api.util.ClientDebugUtil;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.servlet.*;
import org.oa4mp.server.loader.oauth2.storage.RFC8628Store;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Locale;
import java.util.Map;

/**
 * Servlet that <b>starts</b> the RFC 8628 device flow .This issues a user code that the user
 * must present to an authorization endpoint.
 * <p>Created by Jeff Gaynor<br>
 * on 2/9/21 at  11:21 AM
 */
public class RFC8628Servlet extends MultiAuthServlet implements RFC8628Constants2 {
    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        return null;
    }

    @Override
    protected void doIt(HttpServletRequest req, HttpServletResponse resp) throws Throwable {
        ServletDebugUtil.trace(this, "starting device flow");
        OA2SE oa2SE = (OA2SE) OA4MPServlet.getServiceEnvironment();
        if (!oa2SE.isRfc8628Enabled()) {
            ServletDebugUtil.trace(this, "device flow not enabled onthis server");
            throw new OA2ATException(OA2Errors.ACCESS_DENIED,
                    "This service is not available on this server",
                    HttpStatus.SC_SERVICE_UNAVAILABLE,
                    null);
        }
        RFC8628ServletConfig rfc8628ServletConfig = oa2SE.getRfc8628ServletConfig();

        // todo - have the wait period configurable.
/*        long checkTime = System.currentTimeMillis() - lastAttemptTS;
        if (checkTime < rfc8628ServletConfig.interval) {
            throw new OA2GeneralError("too many client requests",
                    "invalid_request", HttpStatus.SC_BAD_REQUEST, null);
        }
        */
        // lastAttemptTS = System.currentTimeMillis();
        // Next two lines also verify that it is a client, has been approved and has the right secret.
        OA2Client client = null;
        String type = req.getParameter(RFC7523Constants.CLIENT_ASSERTION_TYPE);
  //      printAllParameters(req);
        if (type != null && type.equals(RFC7523Constants.ASSERTION_JWT_BEARER)) {
            // If the client is doing an RFC 7523 grant, then it must authorize accordingly.
            client = (OA2Client) OA2HeaderUtils.getAndVerifyRFC7523Client(req, (OA2SE) getServiceEnvironment(), true);
        }else{
            try {
                client = (OA2Client) getClient(req);
            } catch (UnknownClientException unknownClientException) {
                throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                        "unknown client",
                        HttpStatus.SC_BAD_REQUEST,
                        null);
            }
            if (!client.isPublicClient()) {
                try {
                    ClientUtils.verifyClientSecret(client, getClientSecret(req), false);
                } catch (Throwable t) {
                    DebugUtil.error(this, "Error verifying client secret", t);
                    throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                            "incorrect password",
                            HttpStatus.SC_BAD_REQUEST,
                            null, client);
                }
            }

        }
        checkAdminClientStatus(client.getIdentifier());
        MetaDebugUtil debugger = OA4MPServlet.createDebugger(client);
        debugger.trace(this, "is response committed?" + resp.isCommitted());
        debugger.trace(this, "checked client secret.");

        long lifetime = 0 < client.getDfLifetime() ? client.getDfLifetime() : rfc8628ServletConfig.lifetime;
        lifetime = 0 < lifetime ? lifetime : oa2SE.getAuthorizationGrantLifetime(); // if nothing is set, default to AG lifetime.
        AGRequest2 agRequest2 = new AGRequest2(req, lifetime);
        AGResponse agResponse = (AGResponse) getAGI().process(agRequest2);
        AuthorizationGrantImpl ag = ((OA2TokenForge) oa2SE.getTokenForge()).createToken(agRequest2);
        OA2ServiceTransaction t = (OA2ServiceTransaction) getTransactionStore().create();
        t.setOriginalURL(req.getRequestURI() + "?" + req.getQueryString());
        debugger.trace(this, "created transaction \"" + t.getIdentifierString() + "\"");
        t.setClient(client);
        OA2ATServlet.findSigningKey(req, t);
        OA2Client resolvedClient = OA2ClientUtils.resolvePrototypes(oa2SE, client);
        t.setIdentifier(BasicIdentifier.newID(ag.getURIToken()));
        t.setAuthorizationGrant(ag);
        t.setAuthGrantLifetime(lifetime);
        t.setAuthGrantValid(true);
        t.setRFC8628Request(true);
        // Fix https://github.com/ncsa/oa4mp/issues/164
        OA2AuthorizedServletUtil.setupPKCE(req.getParameter(RFC7636Util.CODE_CHALLENGE),
                req.getParameter(RFC7636Util.CODE_CHALLENGE_METHOD),
                oa2SE,
                t,
                client,
                debugger);
        RFC8628State rfc8628State = new RFC8628State();
        String scope = req.getParameter(OA2Constants.SCOPE);
        rfc8628State.originalScopes = scope;
        if(debugger instanceof ClientDebugUtil){
            ((ClientDebugUtil)debugger).setTransaction(t);
        }
        if (StringUtils.isTrivial(scope)) {
            debugger.trace(this, "no scopes, using default for client");
            t.setScopes(client.getScopes());
        } else {
            // scope is optional, so only take notice if they send something
            debugger.trace(this, "checking scopes:" + scope + ". strict scopes " + (client.useStrictScopes() ? "on" : "off"));
            TransactionState transactionState = new TransactionState(req, resp, agResponse.getParameters(), t, null);
            try {
                t.setScopes(ClientUtils.resolveScopes(transactionState, resolvedClient, true, true));
            } catch (OA2RedirectableError redirectableError) {
                throw new OA2ATException(redirectableError.getError(),
                        redirectableError.getDescription(),
                        HttpStatus.SC_BAD_REQUEST,
                        redirectableError.getState(), t.getClient());
            }

        }

        String userCode; //what the user is presented with
        if (oa2SE.getAuthorizationServletConfig().getUseMode().equals(OA4MPConfigTags.AUTHORIZATION_SERVLET_USE_MODE_PROXY)) {
            userCode = ProxyUtils.startProxyDeviceFlow(oa2SE, t, rfc8628State);
            lifetime = rfc8628State.lifetime; // This is set from the proxy and must be propagated to the user.
            // if use local DF consent is false,  can't get callback from DF, hence there can be
            // no local consent page displayed to the user. If we don't set it here, the user will not
            // be able to do any flows.
            t.setConsentPageOK(!oa2SE.getAuthorizationServletConfig().isLocalDFConsent());
        } else {
            userCode = getUserCode(rfc8628ServletConfig);
            // Make sure it is not in use, since the configuration might make collisions possible.
            boolean gotUserCode = false;
            RFC8628Store rfc8628Store = (RFC8628Store) getTransactionStore();
            int userCodeAttemptCount = 5;
            for (int i = 0; i < userCodeAttemptCount; i++) {
                // 5 tries to come up with an unused user code.
                if (rfc8628Store.hasUserCode(userCode)) {
                    ServletDebugUtil.trace(this, "Attempt to get user code # " + i + "failed for \"" + userCode + "\".");
                    userCode = getUserCode(rfc8628ServletConfig);
                } else {
                    gotUserCode = true;
                    break;
                }
            }
            if (!gotUserCode) {
                ServletDebugUtil.error(this, "Could not get an unused user code after " + userCodeAttemptCount + " attempts.");
                throw new OA2ATException(OA2Errors.SERVER_ERROR, "could not create new user code", HttpStatus.SC_BAD_REQUEST, null, t.getClient());
            }
            rfc8628State.lifetime = lifetime;
            if (0 < client.getDfInterval()) {
                rfc8628State.interval = client.getDfInterval();
            } else {
                // interval not set in client, use default.
                rfc8628State.interval = rfc8628ServletConfig.interval;
            }
            rfc8628State.userCode = userCode;
            t.setUserCode(userCode);
        }
        debugger.trace(this, "user_code = " + userCode);
        rfc8628State.issuedAt = System.currentTimeMillis();
        rfc8628State.deviceCode = ag.getURIToken();
        rfc8628State.lastTry = System.currentTimeMillis(); // so it has a reasonable value


        t.setRFC8628State(rfc8628State);

        debugger.trace(this, "saving transaction");
        getTransactionStore().save(t);

        //write the response
        resp.setContentType("application/json;charset=UTF-8");
        resp.setCharacterEncoding("UTF-8");
        JSONObject jsonObject = new JSONObject();
        // CIL-1102 fix
        jsonObject.put(RFC8628Constants.DEVICE_CODE, TokenUtils.b32EncodeToken(ag.getToken()));
        jsonObject.put(RFC8628Constants.USER_CODE, userCode);
        jsonObject.put(RFC8628Constants.EXPIRES_IN, lifetime / 1000); // must be returned in seconds.
        jsonObject.put(RFC8628Constants.INTERVAL, rfc8628State.interval / 1000); // must be returned in seconds.
        jsonObject.put(RFC8628Constants.VERIFICATION_URI, rfc8628ServletConfig.deviceEndpoint);
        jsonObject.put(RFC8628Constants.VERIFICATION_URI_COMPLETE, rfc8628ServletConfig.deviceEndpoint + "?" + RFC8628Constants.USER_CODE + "=" + userCode);
        debugger.trace(this, "done, writing response for " + jsonObject + "\n"); // add a line so logs are cleaner
        resp.getWriter().println(jsonObject.toString(1));
        resp.getWriter().flush();
        resp.getWriter().close();
        resp.setStatus(HttpStatus.SC_OK);
        logOK(req); // CIL-1722
    }

    protected String getClientSecret(HttpServletRequest request) {
        return ClientUtils.getClientSecret(request, getFirstParameterValue(request, OA2Constants.CLIENT_SECRET));
    }

    protected void checkParameters(OA2ServiceTransaction t,
                                   OA2Client client,
                                   AGResponse agResponse, HttpServletRequest req) throws Throwable {
        Map<String, String> params = agResponse.getParameters();

        String rawATLifetime = params.get(OA2Constants.ACCESS_TOKEN_LIFETIME);
        if (!StringUtils.isTrivial(rawATLifetime)) {
            try {
                long at = TimeUtil.getValueSecsOrMillis(rawATLifetime);
                //               long at = Long.parseLong(rawATLifetime);
                t.setRequestedATLifetime(at);
            } catch (Throwable throwable) {
                OA4MPServlet.getServiceEnvironment().info("Could not set request access token lifetime to \"" + rawATLifetime
                        + "\" for client " + client.getIdentifierString());
                // do nothing.
            }
        }
        String rawRefreshLifetime = params.get(OA2Constants.REFRESH_LIFETIME);
        if (!StringUtils.isTrivial(rawRefreshLifetime)) {
            try {
                long rt = TimeUtil.getValueSecsOrMillis(rawRefreshLifetime);
                //long rt = Long.parseLong(rawRefreshLifetime);
                t.setRequestedRTLifetime(rt);
            } catch (Throwable throwable) {
                OA4MPServlet.getServiceEnvironment().info("Could not set request refresh token lifetime to \"" + rawRefreshLifetime
                        + "\" for client " + client.getIdentifierString());
                // do nothing.
            }
        }
        // Scope check. *sigh*
        if (client.isPublicClient()) {
            if (!client.getScopes().contains(OA2Scopes.SCOPE_OPENID)) {
                throw new IllegalAccessException("The " + OA2Scopes.SCOPE_OPENID + " scope is missing from the request.");
            }
        }

    }


    protected static SecureRandom secureRandom = new SecureRandom();


    protected static String getUserCode(RFC8628ServletConfig rfc8628ServletConfig) {
        BigInteger v = new BigInteger(8 * rfc8628ServletConfig.userCodeLength, secureRandom);
        ArrayList<Character> elements = new ArrayList<>();
        int parity = (v.remainder(BigInteger.valueOf(2))).intValue();
        BigInteger currentValue = v.abs(); // just in case
        BigInteger codeCharsLength = BigInteger.valueOf(rfc8628ServletConfig.codeChars.length);
        while (0 <= currentValue.compareTo(BigInteger.ZERO)) {
            if (elements.size() == rfc8628ServletConfig.userCodeLength) {
                break;
            }
            if (-1 == currentValue.compareTo(codeCharsLength)) {
                if (0 < parity) {
                    elements.add(rfc8628ServletConfig.codeChars[currentValue.intValue()]);
                } else {
                    elements.add(0, rfc8628ServletConfig.codeChars[currentValue.intValue()]);
                }
                break; // last iteration
            } else {
                BigInteger[] dr = currentValue.divideAndRemainder(codeCharsLength);
                if (0 < parity) {
                    elements.add(rfc8628ServletConfig.codeChars[dr[1].intValue()]);
                } else {
                    elements.add(0, rfc8628ServletConfig.codeChars[dr[1].intValue()]);
                }
                currentValue = dr[0];
            }

        }
        return addSeperator(elements, rfc8628ServletConfig);
    }

    private static String addSeperator(ArrayList<Character> elements, RFC8628ServletConfig rfc8628ServletConfig) {
        String out = "";
        int j = 0;
        for (Character c : elements) {
            if (0 < j && 0 == (j % rfc8628ServletConfig.userCodePeriodLength)) {
                out = out + rfc8628ServletConfig.userCodeSeperator;
            }
            out = out + c;
            j++;
        }
        return out;
    }

    /**
     * Used in the DB servlet mostly to take whatever the user types in (may or may not
     * include the user code seperator), be in mixed case.
     *
     * @param x
     * @return
     */
    public static String convertToCanonicalForm(String x, RFC8628ServletConfig rfc8628ServletConfig) {
        String[] weedOutChars = new String[]{"-", "+", " ", "_"};
        x = x.trim().toUpperCase(Locale.ROOT);
        for (String cc : weedOutChars) {
            x = x.replace(cc, "");
        }
        String out = "";
        int i = 0;
        boolean isFirstPass = true;
        while (i < x.length()) {
            if (isFirstPass) {
                isFirstPass = false;
                out = x.substring(i, Math.min(i + rfc8628ServletConfig.userCodePeriodLength, x.length()));
            } else {
                out = out + rfc8628ServletConfig.userCodeSeperator + x.substring(i, Math.min(i + rfc8628ServletConfig.userCodePeriodLength, x.length()));
            }
            i = i + rfc8628ServletConfig.userCodePeriodLength;
        }

        return out;
    }

    public static void main(String[] args) {
        long ts = System.currentTimeMillis();
        RFC8628ServletConfig rfc8628ServletConfig = new RFC8628ServletConfig();
        rfc8628ServletConfig.userCodeLength = 12;
        rfc8628ServletConfig.userCodeSeperator = "++";
        rfc8628ServletConfig.userCodePeriodLength = 4;

        System.out.println("code =" + getUserCode(rfc8628ServletConfig));
        System.out.println("current default user code impl:" + getUserCode(rfc8628ServletConfig));

/*
        for (int i = 1; i <= 10; i++) {
            byte[] b = new byte[i];
            secureRandom.nextBytes(b);
            BigInteger bigInteger = new BigInteger(b);
            System.out.println("code #" + i + ", " + (8 * i) + " bits =" + getUserCode(bigInteger));
        }*/
        String x = "    https://oa4mp.bigstate.edu:9443/oauth2/781ae055ce3ba811b05b8c9522a09d31?type=authzGrant&amp;ts=1610837891182&amp;version=v2.0&amp;lifetime=12345000";

        String secret = DigestUtils.sha1Hex(x);
        for (int i = 0; i < 10; i++) {
            //BigInteger bi = new BigInteger(40, secureRandom);
            //BigInteger bi = new BigInteger(secret, 16);
            System.out.println("11 chars =" + getUserCode(rfc8628ServletConfig));
        }
        System.out.println("canonical form for 23bcd = " + convertToCanonicalForm("23bcd", rfc8628ServletConfig));
        System.out.println("canonical form for abcdg0w4 = " + convertToCanonicalForm("abcdg0w4", rfc8628ServletConfig));
        System.out.println("canonical form for a----b-c = " + convertToCanonicalForm("a----b-c", rfc8628ServletConfig));

    }
}
