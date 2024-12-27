package org.oa4mp.server.loader.qdl.claims;

import org.oa4mp.server.loader.oauth2.claims.ScopeTemplateUtil;
import org.qdl_lang.exceptions.BadArgException;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLStem;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/22/21 at  2:30 PM
 */
public class TemplateSubsitutionQDLUtil implements QDLFunction {

    public static final String TEMPLATE_SUBSTITUTION_NAME = "template_substitution";

    @Override
    public String getName() {
        return TEMPLATE_SUBSTITUTION_NAME;
    }

    @Override
    public int[] getArgCount() {
        return new int[]{2, 3};
    }

    @Override
    public Object evaluate(Object[] objects, State state) {
        QDLStem arg = null;
        if(objects[0] instanceof String){
            arg = new QDLStem();
            arg.listAdd(objects[0]);
        }else if(objects[0] instanceof QDLStem){
            arg = (QDLStem) objects[0];
        }
        if(arg == null){
            throw new BadArgException("error: The first argument must be a string or list of strings",0);
        }
        QDLStem otherClaimStem = (QDLStem) objects[1];
        Map<String, List<String>> groups = new HashMap<>();

        if (objects.length == 3) {
            QDLStem groupClaimStem = (QDLStem) objects[2];
            for (Object key : groupClaimStem.keySet()) {
                QDLStem ss = (QDLStem) groupClaimStem.get(key);
                groups.put(String.valueOf(key), ss.getQDLList().toJSON());
            }
        }
        List<String> out = new ArrayList<>();
        for(Object key: arg.keySet()){
            String rawString = String.valueOf(arg.get(key));
            out.addAll( ScopeTemplateUtil.replaceTemplate(rawString, groups, otherClaimStem));
        }
        QDLStem outStem = new QDLStem();
        outStem.addList(out);

        return outStem;
    }

    @Override
    public List<String> getDocumentation(int argCount) {
        List<String> doxx = new ArrayList<>();
        switch (argCount) {
            case 2:
                doxx.add(getName() + "(arg, scalar_claims.)");
                break;
            case 3:
                doxx.add(getName() + "(arg., scalar_claims., list_claims.)");
                break;
        }
        doxx.add("Output is always a list with all possible substitutions done.");
        doxx.add("arg = a string or stem to be acted upon");
        doxx.add("scalar_claims.  = a stem of the scalar substitutions");


        switch (argCount) {
            case 2:
                doxx.add("Note, you will get back a single string with all possible substitutions done for each argument.");
                doxx.add("E.g. # 1 -- apply to a string");
                doxx.add("Take the raw_string and apply templates to it. So if the string were");
                doxx.add("'storage.read:/home/${uid} and scalar_claims.uid := 'bob', the result would be");
                doxx.add("'storage.read:/home/bob");
                doxx.add("E.g. # 2 -- a simple example for a stem");
                doxx.add("A very simple invocation, with templates in the left argument");
                doxx.add("and a stem consisting of a single substitution:");
                doxx.add("   template_substitution(['a.${u}','b.${u}'],{'u':'x'})");
                doxx.add("[a.x, b.x]");
                doxx.add("If we had a general stem (so not just a list) as the arg, we would");
                doxx.add("still get back a list.");
                break;
            case 3:
                doxx.add("list_claims.  = a stem of the list substitutions. Used for groups.");
                doxx.add("If there are groups (lists of strings), then the first list element that matches");
                doxx.add("will be used. The groups. ");
                doxx.add("Caveat: Be sure that the list_claims. have values simple flat lists of strings,");
                doxx.add("        since this get handed off");
                doxx.add("        to Java, which cannot understand complex stems.");
                doxx.add("You will get back a list of strings for each argument, one for each group found.");
                doxx.add("");
                doxx.add("E.g. # 1 - splitting up claims");
                doxx.add("Assuming you have claims in a stem called claims. you can split off the groups by");
                doxx.add("   grps. := include_keys(claims., list_keys(claims., false));");
                doxx.add("Similarly, to split off the claims");
                doxx.add("   c2. := include_keys(claims., list_keys(claims., true))");
                doxx.add("To process the variable named raw_string:");
                doxx.add("   "+getName() + "(raw_string, c2., grps.);");
                doxx.add("E.g. # 2 -- a direct example");
                doxx.add("  raw:='storage.read:/bsu/${isMemberOf}/${uid}';");
                doxx.add("  claims.uid := 'bob';");
                doxx.add("  grps.isMemberOf. := ['all','dune'];");
                doxx.add("  template_substitution(raw, claims., grps.);");
                doxx.add("[storage.read:/bsu/all/bob,storage.read:/bsu/dune/bob]");
                doxx.add("   template_substitution(['a.b/${uid}', 'a.c:/${isMemberOf}/${uid}'], claims., grps.);");
                doxx.add("[a.b/bob,a.c:/all/bob,a.c:/dune/bob]");
                break;
        }

        return doxx;
    }
}
