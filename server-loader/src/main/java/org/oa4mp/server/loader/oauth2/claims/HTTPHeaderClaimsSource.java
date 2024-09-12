package org.oa4mp.server.loader.oauth2.claims;

import org.oa4mp.delegation.server.server.UnsupportedScopeException;
import org.oa4mp.delegation.server.server.claims.ClaimSourceConfiguration;
import org.oa4mp.delegation.server.ServiceTransaction;
import org.qdl_lang.variables.QDLStem;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import java.util.HashMap;

import static edu.uiuc.ncsa.security.core.util.DebugUtil.trace;
import static org.oa4mp.server.loader.qdl.claims.CSConstants.*;

/**
 * This is for the specific case that claims are passed through the headers. Each starts with the caput
 * and every claim with this caput is processed (caput is removed) and added. E.g.
 * <pre>
 *     OIDC_CLAIM_sub
 * </pre>
 * sets the "sub" claim.
 * <p>In short, this filters headers based on a configurable prefix.. Any prefixed header has the
 * prefix removed and the key-value pair returned as a claim. So if there is a header </p>
 * <pre>OIDC_CLAIM_my_claim = foo</pre>
 * <p>Then a claim of "my_claim" with a value of "foo" will be asserted.</p>
 * <h2>Caveat</h2>
 * <p>This may be set in the handler attribute of the server</p>
 * <p>Created by Jeff Gaynor<br>
 * on 3/15/17 at  2:41 PM
 */
public class HTTPHeaderClaimsSource extends BasicClaimsSourceImpl {

    /**
     * Name of the property that contains the prefix used by this source. The default is OIDC_CLAIM_
     * if this is not set.
     */
    public static final String PREFIX_KEY = "prefix";

    public HTTPHeaderClaimsSource(ClaimSourceConfiguration configuration) {
        setConfiguration(configuration);
    }

    // needed for contract creating claim sources from configuration files (no arg constructor required, config injected.)
    public HTTPHeaderClaimsSource() {
        super();
    }

    public HTTPHeaderClaimsSource(QDLStem stem) {
        super(stem);
     }
    public String caput = "OIDC_CLAIM_";

    public String getCaput() {
        return caput;
    }

    public void setCaput(String caput) {
        this.caput = caput;
    }


    @Override
    protected JSONObject realProcessing(JSONObject claims, HttpServletRequest request, ServiceTransaction transaction) throws UnsupportedScopeException {
        String prefix = (String) getConfiguration().getProperty(PREFIX_KEY);
        if (prefix != null) {
            caput = prefix; // caput may be empty
        }
        trace(this, "Omit list = " + getOmitList());
        Enumeration headerNames = request.getHeaderNames();
        String caput = getCaput();
        if (caput == null) {
            caput = ""; // default is empty caput.
        }
        int caputLength = caput.length();
        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement().toString();
            trace(this, "processing claim " + name);
            /*
            The resulting claim is without the caput, so if the caput is "OIDC_CLAIM_" and the header has a field named "OIDC_CLAIM_idp"
            the resulting claim would be called "idp"
             */
            if (name.startsWith(caput)) {
                String key = name.substring(caputLength);
                String value = request.getHeader(name);
                if (!getOmitList().contains(key)) {
                    trace(this, "adding claim " + key + "=" + value);
                    claims.put(key, value);
                } else {
                    trace(this, "OMITTING claim " + key + "=" + value + ", as per omit list");
                }
            }
        }
        return super.realProcessing(claims, request, transaction);
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
    public void fromQDL(QDLStem arg) {
        super.fromQDL(arg);
        HashMap<String, Object> xp = new HashMap<>();

        ClaimSourceConfiguration cfg = new ClaimSourceConfiguration();
        if (arg.containsKey(CS_HEADERS_PREFIX)) {
            xp.put(HTTPHeaderClaimsSource.PREFIX_KEY, arg.getString(CS_HEADERS_PREFIX)); //  wee bit of translation
        }
        cfg.setProperties(xp);
        setConfiguration(cfg);
    }

    @Override
    public QDLStem toQDL() {
        QDLStem arg = super.toQDL();
        arg.put(CS_DEFAULT_TYPE, CS_TYPE_FILTER_HEADERS);
        if (!StringUtils.isTrivial(getCaput())) {
            arg.put(CS_HEADERS_PREFIX, getCaput());
        }
        return arg;
    }
}
