package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.util.functor.JFunctor;

import java.util.ArrayList;
import java.util.Map;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.FunctorClaimsType.IS_MEMBER_OF;

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
        if (claims.containsKey(OA2Claims.IS_MEMBER_OF) && (claims.get(OA2Claims.IS_MEMBER_OF) instanceof Groups)) {
            Groups groups = (Groups) claims.get(OA2Claims.IS_MEMBER_OF);
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
