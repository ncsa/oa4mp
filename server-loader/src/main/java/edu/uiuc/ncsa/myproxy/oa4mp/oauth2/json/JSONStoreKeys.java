package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.json;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

import java.util.List;

/**
 * This has the keys in it for the JSON Store.
 * <p>Created by Jeff Gaynor<br>
 * on 2/20/19 at  9:30 AM
 */
public class JSONStoreKeys extends SerializationKeys {
    /*
    Note that the only surefire way to get the attribute names correct across all possible store implementations is
    to have only lower case names.
     */
      String content = "content";

    public String content(String... x) {
          if (0 < x.length) content = x[0];
          return content;
      }
    @Override
    public List<String> allKeys() {
        List<String> allKeys = super.allKeys();
        allKeys.add(content());
        allKeys.add(creationTimpestamp());
        allKeys.add(lastModified());
        allKeys.add(type());
        return allKeys;
    }
    String type = "type";
    public String type(String... x) {
          if (0 < x.length) type = x[0];
          return type;
      }

    String creationTimestamp = "creation_timestamp";
    public String creationTimpestamp(String... x) {
          if (0 < x.length) creationTimestamp = x[0];
          return creationTimestamp;
      }

    String lastModified = "last_modified";
    public String lastModified(String... x) {
          if (0 < x.length) lastModified= x[0];
          return lastModified;
      }

}
