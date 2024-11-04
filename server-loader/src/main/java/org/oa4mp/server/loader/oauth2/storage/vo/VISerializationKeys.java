package org.oa4mp.server.loader.oauth2.storage.vo;

import edu.uiuc.ncsa.security.storage.monitored.MonitoredKeys;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/16/21 at  8:52 AM
 */

/*
╔═════════════════════════════════════════════════════════════╗
║Re https://github.com/ncsa/oa4mp/issues/216                  ║
║do NOT change the identifier to reflect the rename of virtual║
║organizations to virtual issuers or existing OA4MP           ║
║installs will unrecoverably break!                           ║
║                                                             ║
║These have to remain as legacy artifacts.                    ║
╚═════════════════════════════════════════════════════════════╝
 */
public class VISerializationKeys extends MonitoredKeys {

    public VISerializationKeys() {
        identifier("vo_id"); // sets the default identifier for this
        // Changing this to extend MonitoredKeys requires that we change these
        // or existing stuff breaks.
        lastModifiedTS("last_modified");
        creationTS("created");
    }


    String atIssuer = "at_issuer";
  //  String created = "created";
    String defaultKeyID = "default_key_id";
    String discoveryPath = "discovery_path";
    String issuer = "issuer";
    String jsonWebKeys = "json_web_keys";
 //   String lastModified = "last_modified";
    String title = "title";
    String valid = "valid";

    @Override
    public List<String> allKeys() {
        List<String> all = super.allKeys();
    //    all.add(creationTS());
        all.add(defaultKeyID());
        all.add(discoveryPath());
        all.add(issuer());
        all.add(atIssuer());
        all.add(jsonWebKeys());
    //    all.add(lastModifiedTS());
        all.add(title());
        all.add(valid());
        return all;
    }

    public String atIssuer(String... x) {
        if (0 < x.length) atIssuer = x[0];
        return atIssuer;
    }

    public String defaultKeyID(String... x) {
        if (0 < x.length) defaultKeyID = x[0];
        return defaultKeyID;
    }

    public String discoveryPath(String... x) {
        if (0 < x.length) discoveryPath = x[0];
        return discoveryPath;
    }

    public String issuer(String... x) {
        if (0 < x.length) issuer = x[0];
        return issuer;
    }

    public String jsonWebKeys(String... x) {
        if (0 < x.length) jsonWebKeys = x[0];
        return jsonWebKeys;
    }

    public String title(String... x) {
        if (0 < x.length) title = x[0];
        return title;
    }

    public String valid(String... x) {
        if (0 < x.length) valid = x[0];
        return valid;
    }
}
