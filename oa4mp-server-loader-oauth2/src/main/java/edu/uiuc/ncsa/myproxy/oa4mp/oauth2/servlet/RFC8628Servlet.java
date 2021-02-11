package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.AGResponse;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import edu.uiuc.ncsa.security.oauth_2_0.server.AGRequest2;
import edu.uiuc.ncsa.security.util.configuration.ConfigUtil;
import net.sf.json.JSONObject;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/9/21 at  11:21 AM
 */
public class RFC8628Servlet extends MyProxyDelegationServlet implements RFC8628Constants2 {
    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        return null;
    }

    long lastAttemptTS = -1L; // so the first call to the servlet works, otherwise the check

    static Map<String, String> cache = new HashMap<>();

    /**
     * ONLY call this during servlet initialization.
     * This is very resource intensive and should be called only if absolutely necessary.
     */
    public static void rebuildCache() {
        if (!cache.isEmpty()) {
            // do not reinitialize cache
            return;
        }
        for (Identifier id : getServiceEnvironment().getTransactionStore().keySet()) {
            OA2ServiceTransaction transaction = (OA2ServiceTransaction) getServiceEnvironment().getTransactionStore().get(id);
            if (transaction.isRFC8628Request()) {
                RFC8628State rfc8628State = transaction.getRFC8628State();
                if (!isTrivial(rfc8628State.userCode) && rfc8628State.deviceCode != null) {
                    cache.put(rfc8628State.userCode, rfc8628State.deviceCode.toString());
                }
            }
        }
    }

    @Override
    protected void doIt(HttpServletRequest req, HttpServletResponse resp) throws Throwable {
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        if (!oa2SE.isRfc8628Enabled()) {
            throw new OA2GeneralError(OA2Errors.ACCESS_DENIED,
                    "This service is not available on this server",
                    HttpStatus.SC_SERVICE_UNAVAILABLE,
                    null);
        }
        // todo - have the wait period configurable.
        long checkTime = System.currentTimeMillis() - lastAttemptTS;
        if (checkTime < DEFAULT_WAIT) {
            throw new OA2GeneralError("too many client requests");
        }
        lastAttemptTS = System.currentTimeMillis();
        // Next two lines also verify that it is a client, has been approved and has the right secret.
        OA2Client client = (OA2Client) getClient(req);
        // Boot out public clients at this point???
        ClientUtils.verifyClientSecret(client, getClientSecret(req), false);

        long lifetime = oa2SE.getAuthorizationGrantLifetime();
        AGRequest2 agRequest2 = new AGRequest2(req, lifetime);
        AGResponse agResponse = (AGResponse) getAGI().process(agRequest2);
        AuthorizationGrantImpl ag = ((OA2TokenForge) oa2SE.getTokenForge()).createToken(agRequest2);
        OA2ServiceTransaction t = (OA2ServiceTransaction) getTransactionStore().create();
        t.setClient(client);
        t.setIdentifier(BasicIdentifier.newID(ag.getURIToken()));
        t.setAuthGrantLifetime(lifetime);
        t.setRFC8628Request(true);
        RFC8628State rfc8628State = new RFC8628State();
        String userCode = getUserCode();
        rfc8628State.userCode = userCode;
        rfc8628State.deviceCode = ag.getURIToken();
        rfc8628State.issuedAt = System.currentTimeMillis();
        rfc8628State.lastTry = System.currentTimeMillis(); // so it has a reasonable value
        rfc8628State.lifetime = lifetime;
        rfc8628State.interval = DEFAULT_WAIT; // *may* make this configurable
        cache.put(userCode, ag.getToken());
        String scope = req.getParameter(OA2Constants.SCOPE);
        if (!isTrivial(scope)) {
            // scope is optional, so only take notice if they send something
            TransactionState transactionState = new TransactionState(req, resp, agResponse.getParameters(), t);
            t.setScopes(ClientUtils.resolveScopes(transactionState, true));
        }
        t.setRFC8628State(rfc8628State);
        getTransactionStore().save(t);

        //write the response
        resp.setContentType("application/json;charset=UTF-8");
        resp.setCharacterEncoding("UTF-8");
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(DEVICE_CODE, ag.getToken());
        jsonObject.put(USER_CODE, userCode);
        jsonObject.put(EXPIRES_IN, lifetime / 1000); // must be returned in seconds.
        String serviceAddress = oa2SE.getServiceAddress().toString();
        if (!serviceAddress.endsWith("/")) {
            serviceAddress = serviceAddress + "/";
        }
        String x = serviceAddress + VERIFICATION_URI_ENDPOINT;
        jsonObject.put(VERIFICATION_URI, x);
        resp.getWriter().println(jsonObject.toString(1));
        resp.getWriter().flush();
        resp.getWriter().close();
        resp.setStatus(HttpStatus.SC_OK);

    }

    protected String getClientSecret(HttpServletRequest request) {
        return ClientUtils.getClientSecret(request, getFirstParameterValue(request, CLIENT_SECRET));
    }

    protected void checkParameters(OA2ServiceTransaction t,
                                   OA2Client client,
                                   AGResponse agResponse, HttpServletRequest req) throws Throwable {
        Map<String, String> params = agResponse.getParameters();

        String rawATLifetime = params.get(ACCESS_TOKEN_LIFETIME);
        if (!isTrivial(rawATLifetime)) {
            try {
                long at = ConfigUtil.getValueSecsOrMillis(rawATLifetime);
                //               long at = Long.parseLong(rawATLifetime);
                t.setRequestedATLifetime(at);
            } catch (Throwable throwable) {
                getServiceEnvironment().info("Could not set request access token lifetime to \"" + rawATLifetime
                        + "\" for client " + client.getIdentifierString());
                // do nothing.
            }
        }
        String rawRefreshLifetime = params.get(REFRESH_LIFETIME);
        if (!isTrivial(rawRefreshLifetime)) {
            try {
                long rt = ConfigUtil.getValueSecsOrMillis(rawRefreshLifetime);
                //long rt = Long.parseLong(rawRefreshLifetime);
                t.setRequestedRTLifetime(rt);
            } catch (Throwable throwable) {
                getServiceEnvironment().info("Could not set request refresh token lifetime to \"" + rawRefreshLifetime
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

    /**
     * Get a user code with the defaults.
     *
     * @return
     */
    protected static String getUserCode() {
        //      byte[] b = new byte[USER_CODE_DEFAULT_LENGTH];
        //    secureRandom.nextBytes(b);
//        return getUserCode(new BigInteger(b));
        return getUserCode(new BigInteger(44, secureRandom));
    }

    protected static String getUserCode(BigInteger v) {
        ArrayList<Character> elements = new ArrayList<>();
        int parity = (v.remainder(BigInteger.valueOf(2))).intValue();
        BigInteger currentValue = v.abs(); // just in case
        BigInteger codeCharsLength = BigInteger.valueOf(CODE_CHARS.length);
        while (0 <= currentValue.compareTo(BigInteger.ZERO)) {
            if (-1 == currentValue.compareTo(codeCharsLength)) {
                if (0 < parity) {
                    elements.add(CODE_CHARS[currentValue.intValue()]);
                } else {
                    elements.add(0, CODE_CHARS[currentValue.intValue()]);
                }
                break; // last iteration
            } else {
                BigInteger[] dr = currentValue.divideAndRemainder(codeCharsLength);
                if (0 < parity) {
                    elements.add(CODE_CHARS[dr[1].intValue()]);
                } else {
                    elements.add(0, CODE_CHARS[dr[1].intValue()]);
                }
                currentValue = dr[0];
            }

        }
        String out = "";
        int j = 0;
        for (Character c : elements) {
            if (0 < j && 0 == (j % userCodePeriodLength)) {
                out = out + USER_CODE_SEPERATOR_CHAR;
            }
            out = out + c;
            j++;
        }
        return out;
    }

    public static void main(String[] args) {
        long ts = System.currentTimeMillis();
        System.out.println("code =" + getUserCode(BigInteger.valueOf(ts)));
        System.out.println("code 2 =" + getUserCode());
        for (int i = 1; i <= 10; i++) {
            byte[] b = new byte[i];
            secureRandom.nextBytes(b);
            BigInteger bigInteger = new BigInteger(b);
            System.out.println("code #" + i + ", " + (8 * i) + " bits =" + getUserCode(bigInteger));
        }
        String x = "    https://oa4mp.bigstate.edu:9443/oauth2/781ae055ce3ba811b05b8c9522a09d31?type=authzGrant&amp;ts=1610837891182&amp;version=v2.0&amp;lifetime=12345000";

        String secret = DigestUtils.sha1Hex(x);
        BigInteger bi = new BigInteger(44, secureRandom);
        //BigInteger bi = new BigInteger(secret, 16);
        System.out.println("code =" + getUserCode(bi));
        System.out.println(x.length());
        System.out.println(x);

        String y = Base64.getEncoder().encodeToString(x.getBytes(StandardCharsets.UTF_8));
        System.out.println(y.length());
        System.out.println(y);
        System.out.println(getUserCode(new BigInteger(x.getBytes(StandardCharsets.UTF_8))));

    }
}
