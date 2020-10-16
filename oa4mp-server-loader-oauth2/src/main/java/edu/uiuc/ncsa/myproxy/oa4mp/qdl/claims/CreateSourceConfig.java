package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.core.exceptions.IllegalAccessException;

import java.util.ArrayList;
import java.util.List;

/**
 * This fills in all of the missing configuration values with their defaults. Sp the contract is
 * that the argument is a stem with the minimum required parameters. All of those are taken and any
 * missing parameters are supplied.
 * <p>Created by Jeff Gaynor<br>
 * on 2/10/20 at  5:51 AM
 */
public class CreateSourceConfig implements QDLFunction, CSConstants {

    @Override
    public String getName() {
        return "create_source";
    }

    @Override
    public int[] getArgCount() {
        return new int[]{1};
    }

    @Override
    public Object evaluate(Object[] objects, State state) {
        if (objects == null || objects.length == 0) {
            throw new IllegalArgumentException("Error:" + getName() + " requires one argument");
        }

        if (!(objects[0] instanceof StemVariable)) {
            throw new IllegalAccessException("Error:" + getName() + " requires a stem variable as its argument.");
        }
        StemVariable arg = (StemVariable) objects[0];
        if (!arg.containsKey(CS_DEFAULT_TYPE)) {
            throw new IllegalArgumentException("Error: You must specify a type for the claim source");
        }
        StemVariable output = new StemVariable();
        setBasicValues(arg, output);
        switch (arg.getString(CS_DEFAULT_TYPE)) {
            case CS_TYPE_FILE:
                doFS(arg, output);
                break;
            case CS_TYPE_NCSA:
                doNCSA(arg, output);
                break;
            case CS_TYPE_LDAP:
                doLDAP(arg, output);
                break;
            case CS_TYPE_HEADERS:
                doHeaders(arg,output);
                break;
            case CS_TYPE_CODE:
                doCode(arg, output);
                break;
        }
        return output;
    }

    private void doCode(StemVariable arg, StemVariable output) {
        if(! arg.containsKey(CS_CODE_JAVA_CLASS)){
            throw new IllegalArgumentException("Error:" + CS_CODE_JAVA_CLASS + " is required for a custom code configuration.");
        }
        setBasicValues(arg, output);
        output.union(arg);
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
    protected void doNCSA(StemVariable arg, StemVariable output) {
        output.put(CS_LDAP_SERVER_ADDRESS, "ldap4.ncsa.illinois.edu,ldap2.ncsa.illinois.edu,ldap1.ncsa.illinois.edu");
        output.put(CS_LDAP_PORT, 636L);
        output.put(CS_DEFAULT_TYPE, "ldap");
        output.put(CS_LDAP_SEARCH_NAME, "uid"); //
        output.put(CS_LDAP_SEARCH_FILTER_ATTRIBUTE, "uid");
        output.put(CS_DEFAULT_IS_ENABLED, Boolean.TRUE);
        output.put(CS_DEFAULT_FAIL_ON_ERROR, Boolean.FALSE); // failures are not show stoppers
        output.put(CS_DEFAULT_NOTIFY_ON_FAIL, Boolean.TRUE); // tell us all about it though.
        output.put(CS_LDAP_SEARCH_BASE, "ou=People,dc=ncsa,dc=illinois,dc=edu");
        StemVariable searchAtt = new StemVariable();
        searchAtt.put(0L, "mail");
        searchAtt.put(1L, "uid");
        searchAtt.put(2L, "uidNumber");
        searchAtt.put(3L, "cn");
        searchAtt.put(4L, "memberOf");
        output.put("search_attributes.", searchAtt);
        StemVariable groups = new StemVariable();
        groups.put(0L, "memberOf");
        output.put("groups.", groups);
        output.union(arg);

    }

    private void doHeaders(StemVariable arg, StemVariable output) {
        output.union(arg);
    }


    protected void doLDAP(StemVariable arg, StemVariable output) {
        if (!arg.containsKey(CS_LDAP_SERVER_ADDRESS)) {
            throw new IllegalArgumentException("Error:" + CS_LDAP_SERVER_ADDRESS + " is required for ldap configurations");
        }
        setValue(arg,output, CS_LDAP_CONTEXT_NAME,"");
        output.union(arg);
    }

    /**
     * Case where the key in the argument is the same as the key in the configuration stem
     *
     * @param arg
     * @param config
     * @param argKey
     */
    protected void setValue(StemVariable arg, StemVariable config, String argKey) {
        setValue(arg, config, argKey, argKey);
    }



    protected void doFS(StemVariable arg, StemVariable output) {
        if (!arg.containsKey(CS_FILE_FILE_PATH)) {
            throw new IllegalArgumentException("Error: No " + CS_FILE_FILE_PATH + " specified. You must specify this.");
        }
        setValue(arg, output, CS_FILE_FILE_PATH, null);
        output.union(arg);
    }

   protected void setValue(StemVariable arg, StemVariable output, String key, Object defaultValue) {
        if (arg == null) {
            output.put(key, defaultValue);
            return;
        }
        output.put(key, arg.getOrDefault(key, defaultValue));
    }

    /**
     * These are the basic value for every configuration.
     * @param arg
     * @param output
     */
    protected void setBasicValues(StemVariable arg, StemVariable output) {
        setValue(arg, output, CS_DEFAULT_TYPE, CS_DEFAULT_TYPE);
        setValue(arg, output, CS_DEFAULT_IS_ENABLED, Boolean.TRUE);
        setValue(arg, output, CS_DEFAULT_FAIL_ON_ERROR, Boolean.FALSE);
        setValue(arg, output, CS_DEFAULT_NOTIFY_ON_FAIL, Boolean.TRUE);
        setValue(arg, output, CS_DEFAULT_ID, CS_DEFAULT_ID_VALUE);
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
        StemVariable mystem = new StemVariable();
        mystem.put(CS_DEFAULT_TYPE, CS_TYPE_LDAP);
        mystem.put(CS_LDAP_SERVER_ADDRESS, "ldap-test2.ncsa.illinois.edu");
        mystem.put(CS_LDAP_AUTHZ_TYPE, "none");
        mystem.put(CS_LDAP_SEARCH_NAME, "username");
        ArrayList<Object> searchAttr = new ArrayList<>();
        searchAttr.add("mail");
        searchAttr.add("uid");
        searchAttr.add("uidNumber");
        searchAttr.add("cn");
        searchAttr.add("memberOf");
        StemVariable sa = new StemVariable();
        sa.addList(searchAttr);
        StemVariable groupNames = new StemVariable();
        groupNames.put("0", "memberOf");
        mystem.put(CS_LDAP_SEARCH_ATTRIBUTES, sa);
        mystem.put(CS_LDAP_GROUP_NAMES, groupNames);
        mystem.put(CS_LDAP_SEARCH_BASE, "ou=People,dc=ncsa,dc=illinois,dc=edu");

        CreateSourceConfig csc = new CreateSourceConfig();
        System.out.println(((StemVariable) csc.evaluate(new Object[]{"ldap"}, null)).toJSON().toString(1));
        StemVariable out = (StemVariable) csc.evaluate(new Object[]{mystem}, null);
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
