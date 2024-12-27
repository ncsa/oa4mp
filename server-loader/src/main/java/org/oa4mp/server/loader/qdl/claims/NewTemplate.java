package org.oa4mp.server.loader.qdl.claims;

import org.qdl_lang.exceptions.BadArgException;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLStem;

import java.util.ArrayList;
import java.util.List;

/**
 * Creates a template for a given type of claim sourse.
 * This has asterisks where the required values are.
 * <p>Created by Jeff Gaynor<br>
 * on 2/11/20 at  12:29 PM
 */
public class NewTemplate implements QDLFunction, CSConstants {

    public static final String NEW_TEMPLATE_NAME = "new_template";

    @Override
    public String getName() {
        return NEW_TEMPLATE_NAME;
    }

    @Override
    public int[] getArgCount() {
        return new int[]{1};
    }

    public static String REQUIRED_TEMPLATE = "**";


    @Override
    public Object evaluate(Object[] objects, State state) {
        String type = (String) objects[0];
        QDLStem output = new QDLStem();
        switch (type) {
            case CS_TYPE_FILE:
                output.put(CS_DEFAULT_TYPE, CS_TYPE_FILE);
                return output;
            case CS_TYPE_LDAP:
                output = new QDLStem();
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
            case CS_TYPE_FILTER_HEADERS:
                output.put(CS_DEFAULT_TYPE, CS_TYPE_FILTER_HEADERS);
                output.put(CS_HEADERS_PREFIX, REQUIRED_TEMPLATE);
                return output;
            case CS_TYPE_ALL_HEADERS:
                output.put(CS_DEFAULT_TYPE, CS_TYPE_ALL_HEADERS);
                return output;
            case CS_TYPE_CODE:
                output.put(CS_DEFAULT_TYPE, CS_TYPE_CODE);
                output.put(CS_CODE_JAVA_CLASS, REQUIRED_TEMPLATE);
                return output;
        }
        throw new BadArgException("Error: unknown configuration type \"" + type + "\".",0);
    }


    @Override
    public List<String> getDocumentation(int argCount) {
        ArrayList<String> doc = new ArrayList<>();
        doc.add(getName() + "(type) creates a template with the minimum required arguments for a source of this type.");
        doc.add("Generally you use this, then call create_source to add all the other required values before either");
        doc.add("testing it or adding it as a claim source.");
        doc.add("Supported types are:");
        doc.add(CS_TYPE_FILE + " - for file-based claims");
        //doc.add(CS_TYPE_FILTER_HEADERS + " - for claims that are delivered in the HTTP headers. This allows for filtering by prefix.");
        doc.add(CS_TYPE_ALL_HEADERS + " - retrieve all of the headers.");
        doc.add(CS_TYPE_LDAP + " - to get claims from a generic LDAP");
        doc.add(CS_TYPE_NCSA + " - to get claims from the NCSA LDAP (NOTE requires you be on the NCSA internal network!)");
        doc.add(CS_TYPE_CODE + " - for custom written claim sources. (Note: The class must be available in the JVM.)");
        return doc;
    }
}
