package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.functor.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.Groups;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.util.functor.JFunctor;
import net.sf.json.JSONArray;

import java.util.ArrayList;
import java.util.Map;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.functor.claims.FunctorClaimsType.IS_MEMBER_OF;

/**
 * This will check that the user is a member of ever listed group. This accesses the
 * {@link OA2Claims#IS_MEMBER_OF} claim implicitly.
 * <pre>
 *     isMemberOf[g0,g1,g2,...]
 * </pre>
 * returns true if the user is a member of every listed group, false otherwise.
 * <p>Created by Jeff Gaynor<br>
 * on 4/27/18 at  9:11 AM
 */
public class jIsMemberOf extends ClaimFunctor {
    public jIsMemberOf(Map<String, Object> claims) {
        super(IS_MEMBER_OF, claims);
    }

    @Override
    public Object execute() {
        if (claims.containsKey(OA2Claims.IS_MEMBER_OF)) {
            Groups groups = null;
            if(claims.get(OA2Claims.IS_MEMBER_OF)instanceof JSONArray){
                groups = new Groups();
                groups.fromJSON((JSONArray)claims.get(OA2Claims.IS_MEMBER_OF));
            }
            if(claims.get(OA2Claims.IS_MEMBER_OF)instanceof Groups){
                groups = (Groups)claims.get(OA2Claims.IS_MEMBER_OF);
            }
            if(groups == null){
                throw new NFWException("Error: unrecognized group structure in claims");
            }
            boolean isMemberOfAll = true;
            ArrayList<String> targetList = new ArrayList<>();
            for (Object object : getArgs()) {
                if (object instanceof JFunctor) {
                    JFunctor ff = (JFunctor) object;
                    ff.execute();
                    if (ff.getResult() != null) {
                        targetList.add(ff.getResult().toString());
                    }
                } else {
                    targetList.add(object.toString());
                }
            }

            for (String g : targetList) {
                isMemberOfAll = isMemberOfAll && groups.keySet().contains(g);
            }
            result = isMemberOfAll;
        } else {
            result = false;
        }
        executed = true;
        return result;
    }
}
