package test;


import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.Hashtable;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/15/19 at  11:24 AM
 */
class TestAD
{
  static DirContext ldapContext;
  public static void main (String[] args) throws NamingException
  {
    try
    {
      System.out.println("Début du test Active Directory");

      Hashtable<String, String> ldapEnv = new Hashtable<String, String>(11);
      ldapEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
      //ldapEnv.put(Context.PROVIDER_URL,  "ldap://societe.fr:389");
      ldapEnv.put(Context.PROVIDER_URL,  "ldap://ldap.ad.uillinois.edu:389");
      ldapEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
      //ldapEnv.put(Context.SECURITY_PRINCIPAL, "cn=administrateur,cn=users,dc=societe,dc=fr");
      //ldapEnv.put(Context.SECURITY_PRINCIPAL, "cn=jean paul blanc,ou=MonOu,dc=dom,dc=fr");
      ldapEnv.put(Context.SECURITY_PRINCIPAL, "gaynor");
      ldapEnv.put(Context.SECURITY_CREDENTIALS, "pwd");
      //ldapEnv.put(Context.SECURITY_PROTOCOL, "ssl");
      //ldapEnv.put(Context.SECURITY_PROTOCOL, "simple");
      ldapContext = new InitialDirContext(ldapEnv);

        Attributes attrs = ldapContext.getAttributes("cn=gaynor, ou=People", new String[] { "cn" });
        Attribute cnAttr = attrs.get("cn");
        DirContext cnSchema = cnAttr.getAttributeDefinition();


        Attributes cnAttrs = cnSchema.getAttributes("");



      // Create the search controls
      SearchControls searchCtls = new SearchControls();

      //Specify the attributes to return
      String returnedAtts[]={"sn","givenName", "samAccountName"};
      searchCtls.setReturningAttributes(returnedAtts);

      //Specify the search scope
      searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

      //specify the LDAP search filter
      String searchFilter = "(&(objectClass=user))";

      //Specify the Base for the search
      String searchBase = "dc=dom,dc=fr";
      //initialize counter to total the results
      int totalResults = 0;

      // Search for objects using the filter
      NamingEnumeration<SearchResult> answer = ldapContext.search(searchBase, searchFilter, searchCtls);

      //Loop through the search results
      while (answer.hasMoreElements())
      {
        SearchResult sr = (SearchResult)answer.next();

        totalResults++;

        System.out.println(">>>" + sr.getName());
        attrs = sr.getAttributes();
        System.out.println(">>>>>>" + attrs.get("samAccountName"));
      }

      System.out.println("Total results: " + totalResults);
      ldapContext.close();
    }
    catch (Exception e)
    {
      System.out.println(" Search error: " + e);
      e.printStackTrace();
      System.exit(-1);
    }
  }
}