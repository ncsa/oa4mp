package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.ScopeTemplateUtil;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.QDLStem;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/21/21 at  11:11 AM
 */
public class ScopeTemplateQDLUtil {
    public static final String RESOLVE_TEMPLATES_NAME = "resolve_templates";
    public class ResolveTemplates implements QDLFunction{

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
        if(!(objects[0] instanceof QDLStem)){
            throw new IllegalArgumentException("Error: The first argument (for the computed scopes) must be a stem.");
        }
        QDLStem allowedStem =   (QDLStem )objects[0];
        if(!(objects[1] instanceof QDLStem)){
            throw new IllegalArgumentException("Error: The second argument (for the requested scopes) must be a stem.");
        }

        QDLStem requestedStem =   (QDLStem )objects[1];
        if(!(objects[2] instanceof Boolean)){
            throw new IllegalArgumentException("Error: The third argument (if the operation queries available scopes) must be a boolean.");
        }

        Boolean isQuery = (Boolean)objects[2];
        return doIt(allowedStem, requestedStem, isQuery);
    }

    @Override
    public List<String> getDocumentation(int argCount) {
        List<String> doxx = new ArrayList<>();
        doxx.add(getName() +"(allowed_scopes., requested_scopes., is_query)");
        doxx.add("Query or downscope, based on the final argument");
        doxx.add("allowed_scopes. = allowed scopes (e.g. from templates).");
        doxx.add("requested_scopes. = the scopes in the client request.");
        doxx.add("is_query = true if this call is to query available scopes. ");
        doxx.add("E.g. There are two templates");
        doxx.add("   as. :=['x.y:/abc/def','p.q:/rst']");
        doxx.add("   // The requested scopes includes a super-scope of the p.q template");
        doxx.add("   req. := ['x.y:/abc/def/ghi','x.y:/abc/defg', 'p.q:/']");
        doxx.add("   // Setting is_query to false means resolve only sub-scopes");
        doxx.add("  resolve_templates(as., req., false)");
        doxx.add("[x.y:/abc/def/ghi]");
        doxx.add("   // Setting is_query to true means to interpret super-scopes as");
        doxx.add("   // requests for supported templates");
        doxx.add("  resolve_templates(as., req., true)");
        doxx.add("[p.q:/rst,x.y:/abc/def/ghi]");
        doxx.add("See also: " + DOWNSCOPE_NAME + ", " + QUERY_SCOPES_NAME);
        return doxx;
    }  
    }
    public static final String QUERY_SCOPES_NAME = "query_scopes";
    public class QueryScopes implements QDLFunction{

          @Override
          public String getName() {
              return QUERY_SCOPES_NAME;
          }
      
          @Override
          public int[] getArgCount() {
              return new int[]{2};
          }
      
          @Override
          public Object evaluate(Object[] objects, State state) {
              // 2 stems and a boolean
              if(objects.length != 2){
                  throw new IllegalArgumentException(getName() + " requires 2 arguments");
              }
              if(!(objects[0] instanceof QDLStem)){
                  throw new IllegalArgumentException("Error: The first argument (for the computed scopes) must be a stem.");
              }
              QDLStem allowedStem =   (QDLStem )objects[0];
              if(!(objects[1] instanceof QDLStem)){
                  throw new IllegalArgumentException("Error: The second argument (for the requested scopes) must be a stem.");
              }
      
              QDLStem requestedStem =   (QDLStem )objects[1];

              return doIt(allowedStem, requestedStem, true);
          }
      
          @Override
          public List<String> getDocumentation(int argCount) {
              List<String> doxx = new ArrayList<>();
              doxx.add(getName() +"(allowed_scopes., requested_scopes.)");
              doxx.add("Query what scopes are allowed from the computed scopes");
              doxx.add("This is properly done in the authorization so the client knows what is allowed.");
              doxx.add("allowed_scopes. = allowed scopes (e.g. from templates).");
              doxx.add("requested_scopes. = the scopes in the client request.");
              doxx.add("E.g. There are two templates");
              doxx.add("   as. :=['x.y:/abc/def','p.q:/rst']");
              doxx.add("   // The requested scopes includes a super-scope of the p.q template");
              doxx.add("   req. := ['x.y:/abc/def/ghi','x.y:/abc/defg', 'p.q:/']");
              doxx.add("  " + getName() + "(as., req.)");
              doxx.add("[p.q:/rst,x.y:/abc/def/ghi]");
              doxx.add("N.B: " + QUERY_SCOPES_NAME+"('x.,y.) == " + RESOLVE_TEMPLATES_NAME + "(x.,y., true)");
              doxx.add("See also: " + DOWNSCOPE_NAME + ", " + RESOLVE_TEMPLATES_NAME);
              return doxx;
          }
    }
    public static final String DOWNSCOPE_NAME = "downscope";
    public class Downscope implements QDLFunction{

          @Override
          public String getName() {
              return DOWNSCOPE_NAME;
          }
      
          @Override
          public int[] getArgCount() {
              return new int[]{3};
          }
      
          @Override
          public Object evaluate(Object[] objects, State state) {
              // 2 stems and a boolean
              if(objects.length != 2){
                  throw new IllegalArgumentException(getName() + " requires 2 arguments");
              }
              if(!(objects[0] instanceof QDLStem)){
                  throw new IllegalArgumentException("Error: The first argument (for the computed scopes) must be a stem.");
              }
              QDLStem allowedStem =   (QDLStem )objects[0];
              if(!(objects[1] instanceof QDLStem)){
                  throw new IllegalArgumentException("Error: The second argument (for the requested scopes) must be a stem.");
              }
      
              QDLStem requestedStem =   (QDLStem )objects[1];
              return doIt(allowedStem, requestedStem, false);
          }
      
          @Override
          public List<String> getDocumentation(int argCount) {
              List<String> doxx = new ArrayList<>();
              doxx.add(getName() +"(allowed_scopes., requested_scopes.)");
              doxx.add("Downscopes from the computed scopes. ");
              doxx.add("allowed_scopes. = allowed scopes (e.g. from templates).");
              doxx.add("requested_scopes. = the scopes in the client request.");
              doxx.add("E.g. There are two templates");
              doxx.add("   as. :=['x.y:/abc/def','p.q:/rst']");
              doxx.add("   // The requested scopes includes a super-scope of the p.q template");
              doxx.add("   req. := ['x.y:/abc/def/ghi','x.y:/abc/defg', 'p.q:/']");
              doxx.add("   // Setting is_query to false means resolve only sub-scopes");
              doxx.add("  resolve_templates(as., req.)");
              doxx.add("[x.y:/abc/def/ghi]");
              doxx.add("N.B: " + DOWNSCOPE_NAME+"('x.,y.) == " + RESOLVE_TEMPLATES_NAME + "(x.,y., false)");
              doxx.add("See also: " + QUERY_SCOPES_NAME + ", " + RESOLVE_TEMPLATES_NAME);
              return doxx;
          }
    }

    protected QDLStem doIt(QDLStem allowedStem, QDLStem requestedStem, boolean isQuery){
        List<String> computedScopes = allowedStem.getQDLList().toJSON();
        List<String> requestedScopes = requestedStem.getQDLList().toJSON();
        Collection<String> returnedScopes = ScopeTemplateUtil.doCompareTemplates(computedScopes,requestedScopes,isQuery);
        List<String> rc = new ArrayList<>();
        rc.addAll(returnedScopes);
        QDLStem output = new QDLStem();
        output.addList(rc);
        return output;
    }
}
