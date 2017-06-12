package edu.uiuc.ncsa.oauth2.test;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.util.JSONUtils;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/9/16 at  5:16 PM
 */
public class ThingTester {
    public static final String DD = "----------------------------------------------------------------------------";
    public static void x() {
         System.out.println(DD);
     }

    public static void main(String[] args) {
       runJSONObjectTest();
    }

    public static void runJSONObjectTest(){
        setExample();
        getExample();
        getResponse();
        ldapExample();
        ldapExample2();
        ldapExampleSSL();
        sslExample();
        adminSetExample();
        adminGetExample();
    }


    public static JSONObject getExample() {
        JSONObject admin = new JSONObject();
        JSONObject adminSecrets = new JSONObject();
        adminSecrets.put("id", "123");
        adminSecrets.put("secret", "456");
        admin.put("admin", adminSecrets);

        JSONObject client = new JSONObject();
        JSONObject clientSecret = new JSONObject();
        clientSecret.put("id", "777");
        client.put("client", clientSecret);

        JSONObject actionItems = new JSONObject();
        actionItems.put("method", "get");
        actionItems.put("type", "attribute");

        JSONArray contentItems = new JSONArray();
        contentItems.add("limited_proxies");
        contentItems.add("callbacks");

        JSONObject api = new JSONObject();
        JSONObject apiItems = new JSONObject();
        apiItems.put("subject", admin);
        apiItems.put("action", actionItems);
        apiItems.put("object", client);
        apiItems.put("content", contentItems);
        api.put("api", apiItems);

        prettyPrint(api);
        return api;

    }

    public static void getResponse() {
        JSONObject resp = new JSONObject();
        resp.put("status", 0);
        JSONObject client = new JSONObject();

        JSONObject contentItems = new JSONObject();
        contentItems.put("id", "777");
        JSONArray cbs = new JSONArray();
        cbs.add("https://a.b.c/client/ready1");
        cbs.add("https://a.b.c/client/ready2");
        contentItems.put("callbacks", cbs);
        contentItems.put("limited_proxies", false);
        client.put("client", contentItems);
        resp.put("content", client);

        prettyPrint(resp);

    }

    public static JSONObject setExample() {

        JSONObject admin = new JSONObject();
        JSONObject adminSecrets = new JSONObject();
        adminSecrets.put("id", "123");
        adminSecrets.put("secret", "456");
        admin.put("admin", adminSecrets);

        JSONObject client = new JSONObject();
        JSONObject clientSecret = new JSONObject();
        clientSecret.put("id", "777");
        client.put("client", clientSecret);

        JSONObject actionItems = new JSONObject();
        actionItems.put("method", "set");
        actionItems.put("type", "attribute");

        JSONObject contentItems = new JSONObject();
        JSONArray cbs = new JSONArray();
        cbs.add("https://a.b.c/client/ready1");
        cbs.add("https://a.b.c/client/ready2");
        contentItems.put("callbacks", cbs);

        JSONArray scopes = new JSONArray();
        scopes.add("openid");
        scopes.add("profile");
        scopes.add("email");
        contentItems.put("scopes", scopes);
        contentItems.put("home_uri", "https://a.b.c/client");
        contentItems.put("error_uri", "https://a.b.c/client/error");
        contentItems.put("limited_proxies", true);
        JSONObject api = new JSONObject();
        JSONObject apiItems = new JSONObject();
        apiItems.put("subject", admin);
        apiItems.put("action", actionItems);
        apiItems.put("object", client);
        apiItems.put("content", contentItems);
        api.put("api", apiItems);

        prettyPrint(api);
        return api;
    }

    private static void prettyPrint(JSONObject api) {
        String out = JSONUtils.valueToString(api, 1, 0);
        System.out.println(out);
        x();
    }

    public static JSONObject sslExample() {
        JSONObject sslContent = new JSONObject();
        sslContent.put("use_java_trust_store", true);
        sslContent.put("tls_version", "1.2");
        sslContent.put("store", "xWJrngnHV-WnsbMuSlvc9CnUiX9rSZB7oFB7rcb_zT2GxlBZ7NlJSOsttcfm-AaN0wWGXYXrR1pJ7yVocHPTw0rX0sre_CySQnh98Kf");
        sslContent.put("password", "reallyBadPassword");
        JSONObject ssl = new JSONObject();
        ssl.put("ssl", sslContent);
        prettyPrint(ssl);
        return ssl;
    }

    public static JSONObject ldapExampleSSL() {
        JSONObject ldapContent = new JSONObject();
        ldapContent.put("authorization_type", "none");
        ldapContent.put("address", "ldap2.bigstate.edu");
        ldapContent.put("port", 636);
        ldapContent.put("search_base", "o=bigstate,dc=co,dc=cilogon,dc=org");

        JSONArray attr = new JSONArray();
        JSONObject attr1 = new JSONObject();
        attr1.put("name", "isMemberOf");
        attr.add(attr1);
        JSONObject attr2 = new JSONObject();
        attr2.put("name", "affiliation");

        attr.add(attr2);
        ldapContent.put("search_attributes", attr);
        JSONObject sslContent = new JSONObject();
        sslContent.put("use_java_trust_store", false);
        sslContent.put("tls_version", "1.1");
        sslContent.put("store", "xWJrngnHV-WnsbMuSlvc9CnUiX9rSZB7oFB7rcb_zT2GxlBZ7NlJSOsttcfm-AaN0wWGXYXrR1pJ7yVocHPTw0rX0sre_CySQnh98Kf");
        sslContent.put("password", "reallyBadPassword");
        ldapContent.put("ssl", sslContent);
        JSONObject ldap = new JSONObject();

        ldap.put("ldap", ldapContent);
        prettyPrint(ldap);
        return ldap;
    }

    public static JSONObject ldapExample2() {
        JSONObject ldap = new JSONObject();
        JSONObject ldapContent = new JSONObject();
        ldapContent.put("authorization_type", "simple");
        ldapContent.put("address", "ldap.bigstate.edu");
        ldapContent.put("port", 636);
        ldapContent.put("principal", "uid=my_oidc_query,ou=system,o=MyLDAP,dc=co,dc=cilogon,dc=org");
        ldapContent.put("password", "changeme");
        ldapContent.put("search_base", "o=bigstate,dc=co,dc=cilogon,dc=org");

        JSONArray attr = new JSONArray();
        JSONObject attr1 = new JSONObject();
        attr1.put("name", "isMemberOf");
        attr.add(attr1);
        JSONObject attr2 = new JSONObject();
        attr2.put("name", "affiliation");

        attr.add(attr2);
        ldapContent.put("search_attributes", attr);
        ldap.put("ldap", ldapContent);
        prettyPrint(ldap);
        return ldap;
    }

    public static JSONObject ldapExample() {
        JSONObject ldap = new JSONObject();
        JSONObject ldapContent = new JSONObject();
        ldapContent.put("authorization_type", "none");
        ldapContent.put("address", "ldap.ncsa.illinois.edu");
        ldapContent.put("port", 636);
        ldapContent.put("search_base", "o=MESS,dc=co,dc=cilogon,dc=org");

        JSONArray attr = new JSONArray();
        JSONObject attr1 = new JSONObject();
        attr1.put("name", "memberOf");
        attr1.put("return_name", "isMemberOf");
        attr1.put("return_as_list", false);
        attr.add(attr1);
        JSONObject attr2 = new JSONObject();
        attr2.put("name", "eduPersonOrcid");
        attr2.put("return_as_list", true);

        attr.add(attr2);
        ldapContent.put("search_attributes", attr);
        ldap.put("ldap", ldapContent);
        prettyPrint(ldap);
                         return ldap;
    }

    public static JSONObject adminSetExample() {
        JSONObject admin = new JSONObject();
        JSONObject adminSecrets = new JSONObject();
        adminSecrets.put("id", "123");
        adminSecrets.put("secret", "456");
        admin.put("admin", adminSecrets);


        JSONObject actionItems = new JSONObject();
        actionItems.put("method", "set");
        actionItems.put("type", "attribute");

        JSONObject contentItems = new JSONObject();
        contentItems.put("vo", "urn:vo/comanage/98627854/ae673b3f8d");
        contentItems.put("issuer", "http://bang.nova.edu");
        JSONObject api = new JSONObject();
        JSONObject apiItems = new JSONObject();
        apiItems.put("subject", admin);
        apiItems.put("action", actionItems);
        apiItems.put("content", contentItems);
        api.put("api", apiItems);

        prettyPrint(api);
        return api;
    }
    public static JSONObject adminGetExample() {
        JSONObject admin = new JSONObject();
        JSONObject adminSecrets = new JSONObject();
        adminSecrets.put("id", "123");
        adminSecrets.put("secret", "456");
        admin.put("admin", adminSecrets);


        JSONObject actionItems = new JSONObject();
        actionItems.put("method", "get");
        actionItems.put("type", "attribute");

        JSONArray contentItems = new JSONArray();

        contentItems.add("vo");
        contentItems.add("issuer");
        JSONObject api = new JSONObject();
        JSONObject apiItems = new JSONObject();
        apiItems.put("subject", admin);
        apiItems.put("action", actionItems);
        apiItems.put("content", contentItems);
        api.put("api", apiItems);

        prettyPrint(api);

        return api;
        // now for the response

    }

}

