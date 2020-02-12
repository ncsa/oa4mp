package edu.uiuc.ncsa.oa2.qdl;

import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.util.StemVariable;

import java.util.ArrayList;
import java.util.List;

/**
 * Creates a template for a given type. This has asterisks where the required values are.
 * <p>Created by Jeff Gaynor<br>
 * on 2/11/20 at  12:29 PM
 */
public class NewTemplate implements QDLFunction, CSConstants {
    @Override
    public String getName() {
        return "new_template";
    }

    @Override
    public int getArgCount() {
        return 1;
    }

    public static String REQUIRED_TEMPLATE = "**";


    @Override
    public Object evaluate(Object[] objects) {
        if (objects.length != 1) {
            throw new IllegalArgumentException("Error:" + getName() + " requires the type of the claim source");
        }
        String type = (String) objects[0];
        StemVariable output = new StemVariable();
        switch (type) {
            case CS_TYPE_FILE:
                output.put(CS_DEFAULT_TYPE, CS_TYPE_FILE);
                output.put(CS_FILE_FILE_PATH, REQUIRED_TEMPLATE);
                return output;
            case CS_TYPE_LDAP:
                output = new StemVariable();
                output.put(CS_DEFAULT_TYPE, CS_TYPE_LDAP);

                output.put(CS_LDAP_SERVER_ADDRESS, REQUIRED_TEMPLATE);
                output.put(CS_LDAP_SEARCH_BASE, REQUIRED_TEMPLATE);
                output.put(CS_LDAP_SEARCH_NAME, REQUIRED_TEMPLATE);
                output.put(CS_LDAP_SEARCH_FILTER_ATTRIBUTE, REQUIRED_TEMPLATE);
                output.put(CS_LDAP_AUTHZ_TYPE, REQUIRED_TEMPLATE);
                return output;
            case CS_TYPE_NCSA:
                output.put(CS_DEFAULT_TYPE, CS_TYPE_NCSA); // That's it!
                return output;
            case CS_TYPE_HEADERS:
                output.put(CS_DEFAULT_TYPE, CS_TYPE_HEADERS);
                output.put(CS_HEADERS_PREFIX, REQUIRED_TEMPLATE);
                return output;
        }
        throw new IllegalArgumentException("Error: unknown configuration type \"" + type + "\".");
    }

    @Override
    public QDLFunction getInstance() {
        return this;
    }

    @Override
    public List<String> getDocumentation() {
        ArrayList<String> doc = new ArrayList<>();
        doc.add(getName() + "(type) creates a template with the minimum required arguments for a source of this type.");
        doc.add("Generally you use this, then call create_source to add all the other required values before either");
        doc.add("testing it or adding it as a claim source.");
        return doc;
    }
}
