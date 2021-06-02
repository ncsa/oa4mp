package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/24/21 at  6:35 AM
 */
public class JPath implements QDLFunction {
    @Override
    public String getName() {
        return "jpath";
    }

    @Override
    public int[] getArgCount() {
        return new int[]{2, 3};
    }

    @Override
    public Object evaluate(Object[] objects, State state) {
        StemVariable stemVariable = (StemVariable) objects[0];
        String query = (String) objects[1];
        Configuration conf = null;
        boolean returnAsPaths = false;
        if (objects.length == 3) {
            returnAsPaths = (Boolean) objects[2];
            conf = Configuration.builder()
                    .options(Option.AS_PATH_LIST).build();
        }
        String output;
        if (returnAsPaths) {
            output = JsonPath.using(conf).parse(stemVariable.toJSON().toString()).read(query).toString();
            output = crappyConverter(output);
        } else {
            output = JsonPath.read(stemVariable.toJSON().toString(), query).toString();
        }
        StemVariable outStem = new StemVariable();
        try {
            JSONArray array = JSONArray.fromObject(output);
            outStem.fromJSON(array);
        } catch (JSONException x) {
            JSONObject jo = JSONObject.fromObject(output);
            outStem.fromJSON(jo);
        }
        return outStem;
    }

    protected String crappyConverter(String indexList) {
        JSONArray arrayIn = JSONArray.fromObject(indexList);
        JSONArray arrayOut = new JSONArray();
        for (int i = 0; i < arrayIn.size(); i++) {
            String x = arrayIn.getString(i);
            x = x.substring(2); // All JSON paths start with a $.
            StringTokenizer tokenizer = new StringTokenizer(x, "[");
            boolean isFirst = true;
            String r = "";
            while (tokenizer.hasMoreTokens()) {
                String nextOne = tokenizer.nextToken();
                if (nextOne.startsWith("'")) {
                    nextOne = nextOne.substring(1);
                }
                nextOne = nextOne.substring(0, nextOne.length() - 1);
                if (nextOne.endsWith("'")) {
                    nextOne = nextOne.substring(0, nextOne.length() - 1);
                }
                if (isFirst) {
                    isFirst = false;
                    r = r + nextOne;
                } else {
                    r = r + StemVariable.STEM_INDEX_MARKER + nextOne;
                }
            }
            arrayOut.add(r);

        }
        return arrayOut.toString();
    }

    /*
        json := file_read('/home/ncsa/dev/ncsa-git/oa4mp/oa4mp-server-admin-oauth2/src/main/resources/json-path.json')
       test. := from_json(json)
       jpath(test., '$..book[?(@.price<10)]'); //list of books less that 10. Note .. means descend until a book key is found
       jpath(test., '$..book.length()'); // Just the length of this
       jpath(test., '$..book[?(@.price <= $[\'expensive\'])]');  // All books in store that are not "expensive" (element in source)
       jpath(test., '$..book[?(@.author =~ /.*REES/i)]'); // 	All books matching regex (ignore case)
       jpath(test., '$.store..price'); // 	All prices. Note this is a list
         jpath(test., '$.store..price', true); //paths to all prices.

     */
    @Override
    public List<String> getDocumentation(int argCount) {
        List<String> doxx = new ArrayList<>();
        switch (argCount) {
            case 2:
                doxx.add(getName() + "(arg., query)");
                break;
            case 3:
                doxx.add(getName() + "(arg., query, returnIndices)");
                break;
        }
        doxx.add("   do a JSON path query on a stem. This allows for quite general searching with a well-defined,");
        doxx.add("   standard syntax.");
        doxx.add("arg. - the stem to process");
        doxx.add("query - a JSON path query");

        switch (argCount) {
            case 2:
                doxx.add("output - a stem of the results found.");
                break;
            case 3:
                doxx.add("returnIndices - if true, then the indices of the result are returned");
                doxx.add("   If false (default) then the actual result is returned");
                doxx.add("output - a list of indices.");
                break;
        }
        doxx.add("This accepts a stem and returns a stem. Since the contents of the result");
        doxx.add("and its structure are determined by the query, it is up to you to unpack");
        doxx.add("the result.");

        return doxx;
    }
}
