package org.oa4mp.server.admin.myproxy.oauth2.tools.migrate;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/25/24 at  7:19 AM
 */
public class MigrateKeys extends SerializationKeys {


    String create_ts = "create_ts";
    String import_ts = "import_ts";
    String store_type = "store_type";
    String path = "path";
    String is_imported = "is_imported";
    String import_code = "import_code";
    String error_message = "error_message";
    String filename = "filename";

    public String create_ts(String... x) {
        if (0 < x.length) create_ts = x[0];
        return create_ts;
    }

    public String import_ts(String... x) {
        if (0 < x.length) import_ts = x[0];
        return import_ts;
    }


    public String store_type(String... x) {
        if (0 < x.length) store_type = x[0];
        return store_type;
    }

    public String path(String... x) {
        if (0 < x.length) path = x[0];
        return path;
    }

    public String is_imported(String... x) {
        if (0 < x.length) is_imported = x[0];
        return is_imported;
    }

    /**
     * If there was an import error. This is false if the import has not been done.
     * @param x
     * @return
     */
    public String import_code(String... x) {
        if (0 < x.length) import_code = x[0];
        return import_code;
    }

    public String error_message(String... x) {
        if (0 < x.length) error_message = x[0];
        return error_message;
    }

    public String filename(String... x) {
        if (0 < x.length) filename = x[0];
        return filename;
    }

    @Override
    public List<String> allKeys() {
        List<String> all = super.allKeys();
        all.add(create_ts());
        all.add(import_ts());
        all.add(store_type());
        all.add(path());
        all.add(is_imported());
        all.add(import_code());
        all.add(error_message());
        all.add(filename());
        return all;
    }

}
