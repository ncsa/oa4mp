package org.oa4mp.server.loader.oauth2.claims;

import edu.uiuc.ncsa.security.core.util.StringUtils;
import net.sf.json.JSONObject;
import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.delegation.server.UserInfo;
import org.oa4mp.delegation.server.server.UnsupportedScopeException;
import org.oa4mp.delegation.server.server.claims.ClaimSource;
import org.oa4mp.delegation.server.server.claims.ClaimSourceConfiguration;
import org.oa4mp.delegation.server.server.claims.OA2Claims;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.servlet.GroupHandler;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;
import org.qdl_lang.variables.QDLStem;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;

import static org.oa4mp.server.loader.qdl.claims.CSConstants.*;
import static org.qdl_lang.variables.StemUtility.put;

/**
 * The most basic implementation of a {@link ClaimSource}.
 * <h3>Extending this class</h3>
 * <p>
 * If you want to write your own custom Java claim source and invoke it, you must extend this class
 * and over-right the {@link #realProcessing(JSONObject, HttpServletRequest, ServiceTransaction)}
 * method. Generally when claims are being gotten, the configuration that is created is passed
 * along faithfully and you may access your custom parameters by invoking {@link ClaimSourceConfiguration#getProperty(String)}.
 * An example is in {@link TestClaimSource}.
 * </p>
 * <p>Created by Jeff Gaynor<br>
 * on 8/17/15 at  4:10 PM
 */
public class BasicClaimsSourceImpl implements ClaimSource {

    // CIL-1550 fix (pending) The actual error message is below.
    private static final long serialVersionUID = -6997152589138221711L;
    /*
    time="2022-11-03T15:21:54Z" level=error msg="failed to refresh identity: oidc: failed to get refresh token:
    oauth2: cannot fetch token: 400 Bad Request\nResponse: {\"error\":\"invalid_request\",\"error_description\":\"
    unable to update claims on token refresh: \\\"org.oa4mp.server.loader.oauth2.claims.BasicClaimsSourceImpl;
    local class incompatible: stream classdesc serialVersionUID = 7915876204663027,
    local class serialVersionUID = -6997152589138221711
    \\\"\",\"state\":\"hbhf2fu7m7bif6j3s6xvbmtou\"}"
     */

    /**
     * This is the list of claims from the headers to omit. In other words, this module will reject these out of hand
     * and never return them in a claims object. This is extremely useful in not having existing claims being over-written
     * (which can happen if something like mod_auth_openidc is acting as an intermediary and adding spurious claims.)
     *
     * @return
     */
    public List<String> getOmitList() {
        if (hasConfiguration()) {
            return getConfiguration().getOmitList();
        } else {
            return new LinkedList<>();
        }
    }

    public void setOmitList(List<String> omitList) {
        getConfiguration().setOmitList(omitList);
    }

    ClaimSourceConfiguration configuration = null;

    @Override
    public void setConfiguration(ClaimSourceConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public ClaimSourceConfiguration getConfiguration() {
        if(configuration == null){
            configuration = new ClaimSourceConfiguration();
        }
        return configuration;
    }

    @Override
    public boolean hasConfiguration() {
        return configuration != null;
    }

    public BasicClaimsSourceImpl(OA2SE oa2SE) {
        this.oa2SE = oa2SE;
    }

    public BasicClaimsSourceImpl() {
    }
    public BasicClaimsSourceImpl(QDLStem stem) {
        fromQDL(stem);
      }
    public BasicClaimsSourceImpl(QDLStem stem, OA2SE oa2SE) {
        this(stem);
        setOa2SE(oa2SE);
      }

    public boolean isEnabled() {
        if (getConfiguration() == null) {
            return false;
        }
        return getConfiguration().isEnabled();
    }

    /**
     * Optionally, the service environment may be injected into a scope handler to get configuration of
     * components, e.g.
     *
     * @return
     */
    public OA2SE getOa2SE() {
        return oa2SE;
    }

    public void setOa2SE(OA2SE oa2SE) {
        this.oa2SE = oa2SE;
    }

    transient OA2SE oa2SE; // do NOT serialize this. Ever.
    Collection<String> scopes;

    @Override
    public Collection<String> getScopes() {
        return scopes;
    }

    /**
     * At the most basic level, this just returns the {@link UserInfo} object passed to it. Override as you deem fit.
     *
     * @param claims
     * @param transaction
     * @return
     * @throws UnsupportedScopeException
     */
    @Override
    public JSONObject process(JSONObject claims, ServiceTransaction transaction) throws UnsupportedScopeException {
        return process(claims, null, transaction);
    }

    /**
     * This also just returns the {@link UserInfo} object passed in. This has some legacy code. If you are writing
     * a custom claim source, you really only need to invoke {@link #realProcessing(JSONObject, HttpServletRequest, ServiceTransaction)}
     * at the right time.
     *
     * @param claims
     * @param request
     * @param transaction
     * @return
     * @throws UnsupportedScopeException
     */
    @Override
    public JSONObject process(JSONObject claims, HttpServletRequest request, ServiceTransaction transaction) throws UnsupportedScopeException {
        OA2ServiceTransaction t = (OA2ServiceTransaction) transaction;
   //     MetaDebugUtil debugger = OA4MPServlet.createDebugger(((OA2ServiceTransaction) transaction).getOA2Client());
     //   debugger.trace(this, "starting real processing");
        realProcessing(claims, request, t); // actual work here
       // debugger.trace(this, "done real processing, claims=" + claims);
//        debugger.trace(this, "returned claims=:" + claims);
        return claims;
    }


    protected GroupHandler groupHandler = null;

    public GroupHandler getGroupHandler() {
        if (groupHandler == null) {
            groupHandler = new GroupHandler(); // default
        }
        return groupHandler;
    }

    public void setGroupHandler(GroupHandler groupHandler) {
        this.groupHandler = groupHandler;
    }

    /**
     * This is the actual place to put your code that only processes the claim source. The {@link #process(JSONObject, HttpServletRequest, ServiceTransaction)}
     * calls wrap this and invoke the pre/post processor for you. Your code should take whatever metadata is for the user
     * and add it to the claims object.
     *
     * @param claims
     * @param request
     * @param transaction
     * @return
     * @throws UnsupportedScopeException
     */
    protected JSONObject realProcessing(JSONObject claims, HttpServletRequest request, ServiceTransaction transaction) throws UnsupportedScopeException {
        return claims;

    }


    @Override
    public void setScopes(Collection<String> scopes) {
        this.scopes = scopes;
    }

    /**
     * returns a (unique) collection of claims.
     *
     * @return
     */
    @Override
    public Collection<String> getClaims() {
        HashSet<String> claims = new HashSet<>();
        claims.add(OA2Claims.ISSUER);
        claims.add(OA2Claims.SUBJECT);
        claims.add(OA2Claims.AUDIENCE);
        claims.add(OA2Claims.ISSUED_AT);
        claims.add(OA2Claims.EMAIL);
        claims.add(OA2Claims.EXPIRATION);

        return claims;
    }

    /**
     * This should usually be false. It is true only for those sources that can <b>ONLY</b>
     * run at authorization, such as {@link HTTPHeaderClaimsSource}, where the information
     * is simply not available in later phases.
     *
     * @return
     */
    @Override
    public boolean isRunOnlyAtAuthorization() {
        return false;
    }



    @Override
    public void fromQDL(QDLStem stem) {
        if (stem.containsKey(CS_DEFAULT_ID)) getConfiguration().setId(stem.getString(CS_DEFAULT_ID));
        if (stem.containsKey(CS_DEFAULT_FAIL_ON_ERROR)) getConfiguration().setFailOnError(stem.getBoolean(CS_DEFAULT_FAIL_ON_ERROR));
        if (stem.containsKey(CS_DEFAULT_NOTIFY_ON_FAIL)) getConfiguration().setNotifyOnFail(stem.getBoolean(CS_DEFAULT_NOTIFY_ON_FAIL));
        if (stem.containsKey(CS_DEFAULT_IS_ENABLED)) getConfiguration().setEnabled(stem.getBoolean(CS_DEFAULT_IS_ENABLED));
        if (stem.containsKey(CS_DEFAULT_NAME)) getConfiguration().setName(stem.getString(CS_DEFAULT_NAME));
        if (stem.containsKey(CS_LDAP_RETRY_COUNT)) {getConfiguration().setRetryCount(Math.toIntExact(stem.getLong(CS_LDAP_RETRY_COUNT)));}
        if (stem.containsKey(CS_LDAP_MAX_RETRY_SLEEP)) {getConfiguration().setMaxWait(stem.getLong(CS_LDAP_MAX_RETRY_SLEEP));}
    }

    @Override
    public QDLStem toQDL() {
        QDLStem stem = new QDLStem();
        addToStem(stem, CS_DEFAULT_TYPE, CS_TYPE_BASIC);
        addToStem(stem, CS_DEFAULT_ID, getConfiguration().getId());
        addToStem(stem, CS_DEFAULT_FAIL_ON_ERROR, getConfiguration().isFailOnError());
        addToStem(stem, CS_DEFAULT_IS_ENABLED, getConfiguration().isEnabled());
        addToStem(stem, CS_DEFAULT_NOTIFY_ON_FAIL, getConfiguration().isNotifyOnFail());
        addToStem(stem, CS_DEFAULT_NAME, getConfiguration().getName());
        addToStem(stem, CS_LDAP_RETRY_COUNT, (long)getConfiguration().getRetryCount());
        addToStem(stem, CS_LDAP_MAX_RETRY_SLEEP, getConfiguration().getMaxWait());
        return stem;
    }
    protected void addToStem(QDLStem stem, String key,  Object value) {
        if(value==null) return;
        if(value instanceof String) {
            if(StringUtils.isTrivial((String)value)) return;
        }
        put(stem, key, value);
    }
}
