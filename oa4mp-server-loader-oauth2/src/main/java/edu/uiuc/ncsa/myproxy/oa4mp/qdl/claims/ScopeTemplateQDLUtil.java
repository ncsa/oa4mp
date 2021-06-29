package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.ScopeTemplateUtil;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.StemVariable;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/21/21 at  11:11 AM
 */
public class ScopeTemplateQDLUtil implements QDLFunction {
    public static final String RESOLVE_TEMPLATES_NAME = "resolve_templates";

    @Override
    public String getName() {
        return RESOLVE_TEMPLATES_NAME;
    }

    @Override
    public int[] getArgCount() {
        return new int[]{3};
    }

    @Override
    public Object evaluate(Object[] objects, State state) {
        // 2 stems and a boolean
        if(objects.length != 3){
            throw new IllegalArgumentException(getName() + " requires 3 arguments");
        }
        if(!(objects[0] instanceof StemVariable)){
            throw new IllegalArgumentException("Error: The first argument (for the computed scopes) must be a stem.");
        }
        StemVariable computedStem =   (StemVariable )objects[0];
        if(!(objects[1] instanceof StemVariable)){
            throw new IllegalArgumentException("Error: The second argument (for the requested scopes) must be a stem.");
        }

        StemVariable requestedStem =   (StemVariable )objects[1];
        if(!(objects[2] instanceof Boolean)){
            throw new IllegalArgumentException("Error: The third argument (if the operation queries available scopes) must be a boolean.");
        }

        Boolean isTX = (Boolean)objects[2];
        List<String> computedScopes = computedStem.getStemList().toJSON();
        List<String> requestedScopes = requestedStem.getStemList().toJSON();
        Collection<String> returnedScopes = ScopeTemplateUtil.doCompareTemplates(computedScopes,requestedScopes,isTX);
        List<String> rc = new ArrayList<>();
        rc.addAll(returnedScopes);
        StemVariable output = new StemVariable();
        output.addList(rc);
        return output;
    }

    @Override
    public List<String> getDocumentation(int argCount) {
        List<String> doxx = new ArrayList<>();
        doxx.add(getName() +"(computed_scopes, requested_scopes, is_query)");
        doxx.add("computed_scopes = scopes from templates that have been resolved.");
        doxx.add("requested_scopes = the scopes the client has requested.");
        doxx.add("is_query = true if this call is to query available scopes. ");
        doxx.add("E.g. There are two templates");
        doxx.add("   cs. :=['x.y:/abc/def','p.q:/rst']");
        doxx.add("   // The requested scopes includes a super-scope of the p.q template");
        doxx.add("   req. := ['x.y:/abc/def/ghi','x.y:/abc/defg', 'p.q:/']");
        doxx.add("   // Setting is_query to false means resolve only sub-scopes");
        doxx.add("  resolve_templates(cs., req., false)");
        doxx.add("[x.y:/abc/def/ghi]");
        doxx.add("   // Setting is_query to true means to interpret super-scopes as");
        doxx.add("   // requests for supported templates");
        doxx.add("  resolve_templates(cs., req., true)");
        doxx.add("[p.q:/rst,x.y:/abc/def/ghi]");
        return doxx;
    }
}
