package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.OA2State;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.QDLRuntimeEngine;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.UnsupportedScopeException;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.ClaimSourceConfiguration;
import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.qdl.variables.QDLStem;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;

import java.util.HashMap;

import static edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims.CSConstants.*;

/**
 * This will return all the headers as a stem.
 */
public class QDLHeadersClaimsSource extends BasicClaimsSourceImpl {
    public static final String PREFIX_KEY = "prefix";
    public static final String REGEX_KEY = "regex";

    public QDLHeadersClaimsSource(ClaimSourceConfiguration configuration) {
        setConfiguration(configuration);
    }

    // needed for contract creating claim sources from configuration files (no arg constructor required, config injected.)
    public QDLHeadersClaimsSource() {
        super();
    }

    public QDLHeadersClaimsSource(QDLStem stem) {
        super(stem);
    }

    public String getPrefix() {
        if(prefix == null){
            prefix = "oidc_claim_"; // default
        }
        return prefix;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    String prefix;

      public boolean isRegex(){
          return regex != null;
      }
    public String getRegex() {
        return regex;
    }

    public void setRegex(String regex) {
        this.regex = regex;
    }

    String regex;

    public OA2State getOa2State() {
        return oa2State;
    }

    public void setOa2State(OA2State oa2State) {
        this.oa2State = oa2State;
    }

    OA2State oa2State;

    public boolean hasOA2State() {
        return oa2State != null;
    }

    /**
     * Note that this will filter as a prefix or as a regex depending on the configuration. Also,
     * if a prefix, the prefix is removed, but if a regex, the key is not altered. Any found claims
     * are added to the set of claims.
     * @param claims
     * @param request
     * @param transaction
     * @return
     * @throws UnsupportedScopeException
     */
    @Override
    protected JSONObject realProcessing(JSONObject claims, HttpServletRequest request, ServiceTransaction transaction) throws UnsupportedScopeException {
        if (!hasOA2State()) {
            return claims;
        }
        QDLStem authHeaders = (QDLStem) getOa2State().getValue(QDLRuntimeEngine.AUTH_HEADERS_VAR);
        if(authHeaders == null || authHeaders.isEmpty()){
            return claims;
        }

        QDLStem out = new QDLStem();
        for(Object k : authHeaders.keySet()) {
            if (k instanceof String) {
                String key = (String) k;
                if (isRegex()) {
                    if (key.matches(getRegex())) {
                        out.put(key, authHeaders.get(key));
                    }

                } else {
                    if (key.startsWith(getPrefix())) {
                        Object v = authHeaders.get(key);
                        out.put(key.substring(getPrefix().length()), v);
                    }
                }
            }
        }
        claims.putAll((JSONObject)out.toJSON());
        return claims;
    }

    @Override
    public JSONObject process(JSONObject claims, ServiceTransaction transaction) throws UnsupportedScopeException {
        throw new NotImplementedException("A servlet request must be supplied for this handler");
    }

    @Override
    public boolean isRunOnlyAtAuthorization() {
        return true;
    }

    @Override
    public QDLStem toQDL() {
        QDLStem arg = super.toQDL();
        arg.put(CS_DEFAULT_TYPE, CS_TYPE_ALL_HEADERS);
        if (!StringUtils.isTrivial(getPrefix())) {
            if(isRegex()){
                arg.put(CS_HEADERS_REGEX, getPrefix());
            } else{
                arg.put(CS_HEADERS_PREFIX, getPrefix());
            }
        }
        return arg;
    }

    public void fromQDL(QDLStem arg) {
        super.fromQDL(arg);
        HashMap<String, Object> xp = new HashMap<>();

        ClaimSourceConfiguration cfg = new ClaimSourceConfiguration();
        if (arg.containsKey(CS_HEADERS_PREFIX)) {
            setPrefix(arg.getString(CS_HEADERS_PREFIX));
            xp.put(PREFIX_KEY, arg.getString(CS_HEADERS_PREFIX));
        }
        if(arg.containsKey(CS_HEADERS_REGEX)){
            setRegex(arg.getString(CS_HEADERS_REGEX));
            xp.put(REGEX_KEY, arg.getString(CS_HEADERS_REGEX));
        }
        cfg.setProperties(xp);
        setConfiguration(cfg);
    }
}
