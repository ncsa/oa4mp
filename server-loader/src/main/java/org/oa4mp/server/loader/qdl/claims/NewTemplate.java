package org.oa4mp.server.loader.qdl.claims;

import org.qdl_lang.exceptions.BadArgException;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLStem;
import org.qdl_lang.variables.values.QDLValue;

import java.util.ArrayList;
import java.util.List;

import static org.qdl_lang.variables.StemUtility.put;
import static org.qdl_lang.variables.values.QDLValue.asQDLValue;

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
    public QDLValue evaluate(QDLValue[] objects, State state) {
        String type = objects[0].asString();
        QDLStem output = new QDLStem();
        switch (type) {
            case CS_TYPE_FILE:
                put(output,CS_DEFAULT_TYPE, CS_TYPE_FILE);
                return asQDLValue(output);
            case CS_TYPE_LDAP:
                output = new QDLStem();
                put(output,CS_DEFAULT_TYPE, CS_TYPE_LDAP);
                put(output,CS_LDAP_SERVER_ADDRESS, REQUIRED_TEMPLATE);
                put(output,CS_LDAP_SEARCH_BASE, REQUIRED_TEMPLATE);
                put(output,CS_LDAP_SEARCH_NAME, REQUIRED_TEMPLATE);
                put(output,CS_LDAP_SEARCH_FILTER_ATTRIBUTE, REQUIRED_TEMPLATE);
                put(output,CS_LDAP_AUTHZ_TYPE, REQUIRED_TEMPLATE);
                return asQDLValue(output);
            case CS_TYPE_NCSA:
                put(output,CS_DEFAULT_TYPE, CS_TYPE_NCSA); // That's it!
                return asQDLValue(output);
            case CS_TYPE_FILTER_HEADERS:
                put(output,CS_DEFAULT_TYPE, CS_TYPE_FILTER_HEADERS);
                put(output,CS_HEADERS_PREFIX, REQUIRED_TEMPLATE);
                return asQDLValue(output);
            case CS_TYPE_ALL_HEADERS:
                put(output,CS_DEFAULT_TYPE, CS_TYPE_ALL_HEADERS);
                return asQDLValue(output);
            case CS_TYPE_CODE:
                put(output,CS_DEFAULT_TYPE, CS_TYPE_CODE);
                put(output,CS_CODE_JAVA_CLASS, REQUIRED_TEMPLATE);
                return asQDLValue(output);
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
