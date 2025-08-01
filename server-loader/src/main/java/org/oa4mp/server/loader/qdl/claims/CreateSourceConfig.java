package org.oa4mp.server.loader.qdl.claims;

import edu.uiuc.ncsa.security.core.exceptions.IllegalAccessException;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLStem;
import org.qdl_lang.variables.values.BooleanValue;
import org.qdl_lang.variables.values.LongValue;
import org.qdl_lang.variables.values.QDLValue;
import org.qdl_lang.variables.values.StringValue;

import java.util.ArrayList;
import java.util.List;

import static org.qdl_lang.variables.StemUtility.put;
import static org.qdl_lang.variables.values.QDLValue.asQDLValue;

/**
 * This fills in all of the missing configuration values with their defaults. Sp the contract is
 * that the argument is a stem with the minimum required parameters. All of those are taken and any
 * missing parameters are supplied.
 * <p>Created by Jeff Gaynor<br>
 * on 2/10/20 at  5:51 AM
 */
public class CreateSourceConfig implements QDLFunction, CSConstants {

    public static final String CREATE_SOURCE_NAME = "create_source";

    @Override
    public String getName() {
        return CREATE_SOURCE_NAME;
    }

    @Override
    public int[] getArgCount() {
        return new int[]{1};
    }

    @Override
    public QDLValue evaluate(QDLValue[] objects, State state) {
        if (objects == null || objects.length == 0) {
            throw new IllegalArgumentException(getName() + " requires one argument");
        }

        if (!(objects[0].isStem())) {
            throw new IllegalAccessException(getName() + " requires a stem variable as its argument.");
        }
        QDLStem arg = objects[0].asStem();
        if (!arg.containsKey(CS_DEFAULT_TYPE)) {
            throw new IllegalArgumentException("Error: You must specify a type for the claim source");
        }
        QDLStem output = new QDLStem();
        setBasicValues(arg, output);
        switch (arg.getString(CS_DEFAULT_TYPE)) {
            case CS_TYPE_FILE:
                return asQDLValue(doFS(arg, output));
            case CS_TYPE_NCSA:
                return asQDLValue(doNCSA(arg, output));
            case CS_TYPE_LDAP:
                return asQDLValue(doLDAP(arg, output));
            case CS_TYPE_FILTER_HEADERS:
                return asQDLValue(doHeaders(arg, output));
            case CS_TYPE_ALL_HEADERS:
                return asQDLValue(doQDLHeaders(arg, output));
            case CS_TYPE_CODE:
                return asQDLValue(doCode(arg, output));
        }
        return asQDLValue(output);
    }

    private QDLStem doCode(QDLStem arg, QDLStem output) {
        if (!arg.containsKey(CS_CODE_JAVA_CLASS)) {
            throw new IllegalArgumentException("Error:" + CS_CODE_JAVA_CLASS + " is required for a custom code configuration.");
        }
        setBasicValues(arg, output);
        return output.union(arg);
    }

    /*
    {
     auth_type=none,
     address=ldap4.ncsa.illinois.edu,ldap2.ncsa.illinois.edu,ldap1.ncsa.illinois.edu,
     groups.= {
      0=memberOf
     },
     claim_name=uid,
     search_base=ou=People,dc=ncsa,dc=illinois,dc=edu,
     search_attributes.= {
      0=mail,
      1=uid,
      2=uidNumber,
      3=cn,
      4=memberOf
     },
     type=ldap,
     enabled=true,
     ldap_name=uid
    }

     */
    protected QDLStem doNCSA(QDLStem arg, QDLStem output) {
        put(output,CS_LDAP_SERVER_ADDRESS, "ldap4.ncsa.illinois.edu,ldap2.ncsa.illinois.edu,ldap1.ncsa.illinois.edu");
        put(output,CS_LDAP_PORT, 636L);
        put(output,CS_DEFAULT_TYPE, "ldap");
        put(output,CS_LDAP_SEARCH_NAME, "uid"); //
        put(output,CS_LDAP_SEARCH_FILTER_ATTRIBUTE, "uid");
        put(output,CS_DEFAULT_IS_ENABLED, Boolean.TRUE);
        put(output,CS_DEFAULT_FAIL_ON_ERROR, Boolean.FALSE); // failures are not show stoppers
        put(output,CS_DEFAULT_NOTIFY_ON_FAIL, Boolean.TRUE); // tell us all about it though.
        put(output,CS_LDAP_SEARCH_BASE, "ou=People,dc=ncsa,dc=illinois,dc=edu");
        QDLStem searchAtt = new QDLStem();
        put(searchAtt,0L, "mail");
        put(searchAtt,1L, "uid");
        put(searchAtt,2L, "uidNumber");
        put(searchAtt,3L, "cn");
        put(searchAtt,4L, "memberOf");
        // Fix for https://github.com/cilogon/cilogon-java/issues/58 here and for next entry for goups.
        put(output,CS_LDAP_SEARCH_ATTRIBUTES, searchAtt);
        QDLStem groups = new QDLStem();
        put(groups,0L, "memberOf");
        put(output,CS_LDAP_GROUP_NAMES, groups);
        QDLStem renames = new QDLStem();
        put(renames, "memberOf", "isMemberOf");
        put(output, CS_LDAP_RENAME,renames);
        return output.union(arg);
    }

    private QDLStem doHeaders(QDLStem arg, QDLStem output) {
        return output.union(arg);
    }

    private QDLStem doQDLHeaders(QDLStem arg, QDLStem output) {
    return arg;
}
    protected QDLStem doLDAP(QDLStem arg, QDLStem output) {
        if (!arg.containsKey(CS_LDAP_SERVER_ADDRESS)) {
            throw new IllegalArgumentException("Error:" + CS_LDAP_SERVER_ADDRESS + " is required for ldap configurations");
        }
        setValue(arg, output, CS_LDAP_CONTEXT_NAME, new StringValue());
        return output.union(arg);
    }

    /**
     * Case where the key in the argument is the same as the key in the configuration stem
     *
     * @param arg
     * @param config
     * @param argKey
     */
    protected void setValue(QDLStem arg, QDLStem config, String argKey) {
        setValue(arg, config, argKey, asQDLValue(argKey));
    }


    protected QDLStem doFS(QDLStem arg, QDLStem output) {
        if (!arg.containsKey(CS_FILE_FILE_PATH) && !arg.containsKey(CS_FILE_STEM_CLAIMS)) {
            throw new IllegalArgumentException("Error: No " + CS_FILE_FILE_PATH + " specified. You must specify this.");
        }
        if(arg.containsKey(CS_FILE_FILE_PATH)) {
            setValue(arg, output, CS_FILE_FILE_PATH, null);
        }
        return output.union(arg);
    }

    protected void setValue(QDLStem arg, QDLStem output, String key, QDLValue defaultValue) {
        if (arg == null) {
            output.put(key, defaultValue);
            return;
        }
        output.put(key, arg.getOrDefault(key, defaultValue));
    }

    /**
     * These are the basic value for every configuration.
     *
     * @param arg
     * @param output
     */
    protected void setBasicValues(QDLStem arg, QDLStem output) {
        setValue(arg, output, CS_DEFAULT_TYPE, asQDLValue(CS_DEFAULT_TYPE));
        setValue(arg, output, CS_DEFAULT_IS_ENABLED, BooleanValue.True);
        setValue(arg, output, CS_DEFAULT_FAIL_ON_ERROR, BooleanValue.False);
        setValue(arg, output, CS_DEFAULT_NOTIFY_ON_FAIL, BooleanValue.True);
        setValue(arg, output, CS_DEFAULT_ID, asQDLValue(CS_DEFAULT_ID_VALUE));
    }


    @Override
    public List<String> getDocumentation(int argCount) {
        ArrayList<String> docs = new ArrayList<>();
        docs.add(getName() + "(your_values.) -- creates a claim source configuration");
        docs.add("The argument at the least should have a type. The result is a configuration (as a stem)");
        docs.add("with all the required configuration (which may be quite a bit more than your specific values");
        return docs;
    }

    public static void main(String[] args) {
        QDLStem mystem = new QDLStem();
        put(mystem,CS_DEFAULT_TYPE, CS_TYPE_LDAP);
        put(mystem,CS_LDAP_SERVER_ADDRESS, "ldap-test2.ncsa.illinois.edu");
        put(mystem,CS_LDAP_AUTHZ_TYPE, "none");
        put(mystem,CS_LDAP_SEARCH_NAME, "username");
        ArrayList<Object> searchAttr = new ArrayList<>();
        searchAttr.add("mail");
        searchAttr.add("uid");
        searchAttr.add("uidNumber");
        searchAttr.add("cn");
        searchAttr.add("memberOf");
        QDLStem sa = new QDLStem();
        sa.addList(searchAttr);
        QDLStem groupNames = new QDLStem();
        groupNames.put(LongValue.Zero, "memberOf");
        put(mystem,CS_LDAP_SEARCH_ATTRIBUTES, sa);
        put(mystem,CS_LDAP_GROUP_NAMES, groupNames);
        put(mystem,CS_LDAP_SEARCH_BASE, "ou=People,dc=ncsa,dc=illinois,dc=edu");

        CreateSourceConfig csc = new CreateSourceConfig();
        System.out.println(csc.evaluate(new QDLValue[]{new StringValue("ldap")}, null).asStem().toJSON().toString(1));
        QDLStem out = csc.evaluate(new QDLValue[]{asQDLValue(mystem)}, null).asStem();
        System.out.println(out.toJSON().toString(2));

    }

    String rawLDAP = "{\n" +
            "        \"ldap\": {\n" +
            "          \"failOnError\": \"false\",\n" +
            "          \"address\": \"ldap-test2.ncsa.illinois.edu\",\n" +
            "          \"port\": 636,\n" +
            "          \"enabled\": \"true\",\n" +
            "          \"authorizationType\": \"none\",\n" +
            "          \"searchName\": \"foo\",\n" +
            "          \"searchAttributes\": [\n" +
            "            {\n" +
            "              \"name\": \"mail\",\n" +
            "              \"returnAsList\": false,\n" +
            "              \"returnName\": \"email\"\n" +
            "            },\n" +
            "            {\n" +
            "              \"name\": \"uid\",\n" +
            "              \"returnAsList\": false,\n" +
            "              \"returnName\": \"uid\"\n" +
            "            },\n" +
            "            {\n" +
            "              \"name\": \"uid\",\n" +
            "              \"returnAsList\": false,\n" +
            "              \"returnName\": \"uid\"\n" +
            "            },\n" +
            "            {\n" +
            "              \"name\": \"uidNumber\",\n" +
            "              \"returnAsList\": false,\n" +
            "              \"returnName\": \"uidNumber\"\n" +
            "            },\n" +
            "            {\n" +
            "              \"name\": \"cn\",\n" +
            "              \"returnAsList\": false,\n" +
            "              \"returnName\": \"name\"\n" +
            "            },\n" +
            "            {\n" +
            "              \"name\": \"memberOf\",\n" +
            "              \"IsInGroup\": true,\n" +
            "              \"returnAsList\": false,\n" +
            "              \"returnName\": \"isMemberOf\"\n" +
            "            }\n" +
            "          ],\n" +
            "          \"searchBase\": \"ou=People,dc=ncsa,dc=illinois,dc=edu\",\n" +
            "          \"contextName\": \"\",\n" +
            "          \"ssl\": {\n" +
            "            \"tlsVersion\": \"TLS\",\n" +
            "            \"useJavaTrustStore\": true\n" +
            "          },\n" +
            "          \"name\": \"3258ed63b62d1a78\"\n" +
            "        }\n" +
            "      }";
}
