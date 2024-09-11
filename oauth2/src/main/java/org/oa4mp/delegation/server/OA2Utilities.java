package org.oa4mp.delegation.server;

import net.sf.json.JSONArray;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/2/13 at  11:58 AM
 */
public class OA2Utilities {
    /**
     * Returns the parameters from the request as key value pairs.
     *
     * @param request
     * @return
     */
    public static Map getParameters(HttpServletRequest request) {
        Map<String, String> returnedMap = new HashMap<String, String>();
        Map map = request.getParameterMap();
        // Problem is that these are possibly arrays of strings, so later there are funky class cast exceptions.
        for (Object obj : map.keySet()) {
            String key = obj.toString();
            returnedMap.put(key, getParam(request, key));
        }
        return returnedMap;
    }

    public static String getParam(HttpServletRequest req, String key){
          String[] values  = req.getParameterValues(key);
          if(values == null || values.length == 0) return null;

          if(1 < values.length){
              JSONArray array = new JSONArray();
              for(String x : values){
                  array.add(x);
              }
            return array.toString();
          }
          return values[0];
      }
}
