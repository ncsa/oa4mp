package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.util.configuration.TemplateUtil;
import edu.uiuc.ncsa.security.util.functor.JFunctor;
import edu.uiuc.ncsa.security.util.functor.JFunctorFactory;
import net.sf.json.JSONObject;

import java.util.HashMap;

/**
 * A Claims Aware functor factory. This will replace templates with their values
 * based on the claims supplied in a hashmap.
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  10:09 AM
 */
public class CAFunctorFactory extends JFunctorFactory {
    public CAFunctorFactory(HashMap<String, String> claims) {
        this.claims = claims;
    }

    HashMap<String, String> claims;

    public boolean hasClaims() {
        return claims != null;
    }

    @Override
    protected String preprocess(String x) {
        return TemplateUtil.replaceAll(x, claims);
    }

    @Override
    protected JFunctor figureOutFunctor(JSONObject rawJson) {
        JFunctor ff = super.figureOutFunctor(rawJson);
        if (ff != null) {
            // already got one.
            return ff;
        }
        if (rawJson.containsKey("exclude")) {
            ff = new jExclude(claims);
        }
        if (rawJson.containsKey("$include")) {
            ff = new jInclude(claims);
        }
        if (rawJson.containsKey("$set")) {
            ff = new jSet(claims);
        }
        return ff;
    }
}
