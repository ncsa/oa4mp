package org.oa4mp.server.loader.qdl.claims;

import org.oa4mp.server.loader.oauth2.claims.ScopeTemplateUtil;
import org.qdl_lang.evaluate.StemEvaluator;
import org.qdl_lang.evaluate.StringEvaluator;
import org.qdl_lang.exceptions.BadArgException;
import org.qdl_lang.expressions.ConstantNode;
import org.qdl_lang.expressions.Polyad;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLStem;
import org.qdl_lang.variables.values.LongValue;
import org.qdl_lang.variables.values.QDLValue;
import org.qdl_lang.variables.values.StemValue;
import org.qdl_lang.variables.values.StringValue;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.qdl_lang.variables.values.QDLValue.asQDLValue;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/21/21 at  11:11 AM
 */
public class ScopeTemplateQDLUtil implements Serializable {
    public static final String RESOLVE_TEMPLATES_NAME = "resolve_templates";

    public class ResolveTemplates implements QDLFunction {

        @Override
        public String getName() {
            return RESOLVE_TEMPLATES_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{3};
        }

        @Override
        public QDLValue evaluate(QDLValue[] objects, State state) {
            // 2 stems and a boolean

            if(objects[0] == null || objects[0].isNull()){
                // no computed scopes
                return new StemValue(); // no computed scopes means nothing to return.
            }

            if (!(objects[0].isStem())) {
                throw new BadArgException(" " + getName() +"(0)  (computed scopes) must be a stem, got a '" + objects[0] + "'",0);
            }
            QDLStem allowedStem = objects[0].asStem();
            if(allowedStem.isEmpty()){
                return new StemValue();
            }
            if (!(objects[1].isStem())) {
                throw new BadArgException(" " + getName() + "(1) (requested scopes)  must be a stem, got a '" + objects[1] + "'",1);
            }

            QDLStem requestedStem = objects[1].asStem();
            if(requestedStem.isEmpty()){
                return new StemValue();
            }
            if (!(objects[2].isBoolean())) {
                throw new BadArgException(" " + getName() + "(2) (queries available scopes?)  must be a boolean, got '" + objects[2] + "'.",2);
            }

            Boolean isQuery = objects[2].asBoolean();
            return asQDLValue(doIt(allowedStem, requestedStem, isQuery));
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(allowed_scopes., requested_scopes., is_query)");
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

    public class QueryScopes implements QDLFunction {

        @Override
        public String getName() {
            return QUERY_SCOPES_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{2};
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(allowed_scopes., requested_scopes.)");
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
            doxx.add("N.B: " + QUERY_SCOPES_NAME + "('x.,y.) == " + RESOLVE_TEMPLATES_NAME + "(x.,y., true)");
            doxx.add("See also: " + DOWNSCOPE_NAME + ", " + RESOLVE_TEMPLATES_NAME);
            return doxx;
        }

        @Override
        public QDLValue evaluate(QDLValue[] objects, State state) {
            // 2 stems and a boolean
            if (!(objects[0].isStem())) {
                throw new BadArgException("Error: The first argument (for the computed scopes) must be a stem.",0);
            }
            QDLStem allowedStem = objects[0].asStem();
            if (!(objects[1].isStem())) {
                throw new BadArgException("Error: The second argument (for the requested scopes) must be a stem.",1);
            }

            QDLStem requestedStem =  objects[1].asStem()  ;

            return asQDLValue(doIt(allowedStem, requestedStem, true));
        }
    }

    public static final String DOWNSCOPE_NAME = "downscope";

    public class Downscope implements QDLFunction {

        @Override
        public String getName() {
            return DOWNSCOPE_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{2};
        }

        @Override
        public QDLValue evaluate(QDLValue[] objects, State state) {
            // 2 stems and a boolean

            if (!(objects[0].isStem())) {
                throw new BadArgException("Error: The first argument (for the computed scopes) must be a stem.",0);
            }
            QDLStem allowedStem = objects[0].asStem();
            if (!(objects[1].isStem())) {
                throw new BadArgException("Error: The second argument (for the requested scopes) must be a stem.",1);
            }

            QDLStem requestedStem = objects[1].asStem();
            return asQDLValue(doIt(allowedStem, requestedStem, false));
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(allowed_scopes., requested_scopes.)");
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
            doxx.add("N.B: " + DOWNSCOPE_NAME + "('x.,y.) == " + RESOLVE_TEMPLATES_NAME + "(x.,y., false)");
            doxx.add("See also: " + QUERY_SCOPES_NAME + ", " + RESOLVE_TEMPLATES_NAME);
            return doxx;
        }
    }

    protected QDLStem doIt(QDLStem allowedStem, QDLStem requestedStem, boolean isQuery) {
        List<String> computedScopes = allowedStem.getQDLList().toJSON();
        List<String> requestedScopes = requestedStem.getQDLList().toJSON();
        Collection<String> returnedScopes = ScopeTemplateUtil.doCompareTemplates(computedScopes, requestedScopes, isQuery);
        List<String> rc = new ArrayList<>();
        rc.addAll(returnedScopes);
        QDLStem output = new QDLStem();
        output.addList(rc);
        return output;
    }

    public static final String TO_SCOPE_STRING_NAME = "to_scope_string";

    public class ToScopeString implements QDLFunction {
        @Override
        public String getName() {
            return TO_SCOPE_STRING_NAME;

        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        /**
         * This could be done with QDL, but we want it instantly available in this module.
         * @param objects
         * @param state
         * @return
         */
        @Override
        public QDLValue evaluate(QDLValue[] objects, State state) {
            QDLStem parameters;
            if (objects[0].isStem()) {
                parameters = objects[0].asStem();
            } else {
                throw new BadArgException(TO_SCOPE_STRING_NAME + " requires a stem as its argument",0);
            }
            //access_token.'scope' := detokenize(unique(permissions.), ' ', 2); // turn in to string, omit
            Polyad unique = new Polyad(StemEvaluator.UNIQUE_VALUES);
            unique.addArgument(new ConstantNode(asQDLValue(parameters)));
            Polyad detokenize = new Polyad(StringEvaluator.DETOKENIZE);
            detokenize.addArgument(unique);
            detokenize.addArgument(new ConstantNode(new StringValue(" ")));
            detokenize.addArgument(new ConstantNode(new LongValue(2L)));
            detokenize.evaluate(state);


            return detokenize.getResult();
        }

        List<String> doxx = null;

        @Override
        public List<String> getDocumentation(int argCount) {
            if (doxx == null) {
                doxx = new ArrayList<>();
                doxx.add(TO_SCOPE_STRING_NAME + "(scopes.) - convert a list of scopes to an OAuth string of scopes.");
                doxx.add("In OAuth, the scope value is a blank delimited string. ");
                doxx.add("E.g.");
                doxx.add("    " + TO_SCOPE_STRING_NAME + "(['openid','profile']);");
                doxx.add("openid profile");
                doxx.add("This is a string with blanks between the arguments.");
            }
            return doxx;
        }
    }
}
