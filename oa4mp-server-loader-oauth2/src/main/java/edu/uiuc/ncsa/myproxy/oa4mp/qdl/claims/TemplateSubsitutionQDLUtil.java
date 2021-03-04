package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.ScopeTemplateUtil;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.StemVariable;

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
        StemVariable arg = null;
        if(objects[0] instanceof String){
            arg = new StemVariable();
            arg.listAppend(objects[0]);
        }else if(objects[0] instanceof StemVariable){
            arg = (StemVariable) objects[0];
        }
        if(arg == null){
            throw new IllegalArgumentException("error: The first argument must be a string or list of strings");
        }
        StemVariable otherClaimStem = (StemVariable) objects[1];
        Map<String, List<String>> groups = new HashMap<>();

        if (objects.length == 3) {
            StemVariable groupClaimStem = (StemVariable) objects[2];
            for (String key : groupClaimStem.keySet()) {
                StemVariable ss = (StemVariable) groupClaimStem.get(key);
                groups.put(key, ss.getStemList().toJSON());
            }
        }
        List<String> out = new ArrayList<>();
        for(String key: arg.keySet()){
            String rawString = arg.getString(key);
            out.addAll( ScopeTemplateUtil.replaceTemplate(rawString, groups, otherClaimStem));
        }
        StemVariable outStem = new StemVariable();
        outStem.addList(out);

        return outStem;
    }

    @Override
    public List<String> getDocumentation(int argCount) {
        List<String> doxx = new ArrayList<>();
        switch (argCount) {
            case 2:
                doxx.add(getName() + "(raw_string | stem., simple_claims.");
                break;
            case 3:
                doxx.add(getName() + "(raw_string | stem., simple_claims.[,  group_claims.]");
                break;
        }
        doxx.add("raw_string = string to be acted upon");
        doxx.add("stem.  = a list of strings to be acted upon");


        switch (argCount) {
            case 2:
                doxx.add("Note, you will get back a single string with all possible substitutions done for each argument.");
                doxx.add("E.g. #1");
                doxx.add("Take the raw_string and apply templates to it. So if the string were");
                doxx.add("'storage.read:/home/${uid} and simple_claims.uid := 'bob', the result would be");
                doxx.add("'storage.read:/home/bob");
                break;
            case 3:
                doxx.add("If there are groups (lists of strings), then the first list element that matches");
                doxx.add("Caveat: Be sure that the group_claims. have values simple flat lists of strings,");
                doxx.add("        since this get handed off");
                doxx.add("        to Java, which cannot understand complex stems.");
                doxx.add("You will get back a list of strings for each argument, one for each group found.");
                doxx.add("E.g. #1");
                doxx.add("If you have claims in an stem called claims. ");
                doxx.add("grps. := include_keys(claims., list_keys(claims., false));");
                doxx.add("would return all groups. Similarly, ");
                doxx.add("c2. := include_keys(claims., list_keys(claims., true))");
                doxx.add("would return all scalar-valued claims. If you wanted to process the ");
                doxx.add("variable named raw_string, issue");
                doxx.add(getName() + "(raw_string, c2., grps.);");
                doxx.add("E.g. #2");
                doxx.add("  raw:='storage.read:/bsu/${isMemberOf}/${uid}';");
                doxx.add("  claims.uid := 'bob';");
                doxx.add("  grps.isMemberOf. := ['all','dune'];");
                doxx.add("  template_substitution(raw,claims., grps.);");
                doxx.add("[storage.read:/bsu/all/bob,storage.read:/bsu/dune/bob]");
                doxx.add("");
                break;
        }

        return doxx;
    }
}
