package test;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.CAFunctorFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.jExclude;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.jInclude;
import edu.uiuc.ncsa.security.util.JFunctorTest;
import edu.uiuc.ncsa.security.util.functor.logic.jContains;
import edu.uiuc.ncsa.security.util.functor.logic.jExists;
import edu.uiuc.ncsa.security.util.functor.logic.jMatch;
import net.sf.json.JSONObject;
import org.junit.Test;

import java.util.HashMap;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  11:26 AM
 */
public class FunctorTests extends JFunctorTest {
    @Test
    public void testClaims() throws Exception {
        HashMap<String, String> claims = createClaims();
        CAFunctorFactory factory = new CAFunctorFactory(claims);
        // create some functors, turn into JSON then have the factory re-create them and do the
        // replacements
        jExists jExists = new jExists();
        jExists.addArg("${issuer}");
        JSONObject rawExists = jExists.toJSON();
        jExists jExists1 = (jExists) factory.fromJSON(rawExists);
        assert jExists1.getArgs().get(0).equals(claims.get("issuer"));

        jMatch jMatch = new jMatch();
        jMatch.addArg("${aud}");
        jMatch.addArg(claims.get("aud"));
        jMatch jMatch1 = (jMatch) factory.fromJSON(jMatch.toJSON());
        jMatch1.execute();
        assert jMatch1.getBooleanResult();

        jContains jContains = new jContains();
        jContains.addArg("${sub}"); //needle;
        jContains.addArg("$sub${sub}@fnord.org"); //haystack
        jContains jContains1 = (jContains) factory.fromJSON(jContains.toJSON());
        jContains1.execute();
        assert jContains1.getBooleanResult();
    }

    @Test
    public void testIncludeClaims() throws Exception {
        HashMap<String, String> claims = createClaims();
        jInclude jInclude  = new jInclude(claims);
        jInclude.addArg("issuer");
        jInclude.addArg("sub");
        jInclude.execute();
        claims = jInclude.getClaims();
        assert claims.containsKey("issuer");
        assert claims.containsKey("sub");
        assert !claims.containsKey("idp");
        assert !claims.containsKey("aud");
        System.out.println(claims);

    }

    @Test
    public void testExcludeClaims() throws Exception {
        HashMap<String, String> claims = createClaims();
        jExclude jExclude  = new jExclude(claims);
        jExclude.addArg("issuer");
        jExclude.addArg("sub");
        jExclude.execute();
        claims = jExclude.getClaims();
        assert !claims.containsKey("issuer");
        assert !claims.containsKey("sub");
        assert claims.containsKey("idp");
        assert claims.containsKey("aud");

        System.out.println(claims);
    }

    protected HashMap<String, String> createClaims() {
        HashMap<String, String> claims = new HashMap<>();
        claims.put("issuer", getRandomString());
        claims.put("aud", getRandomString());
        claims.put("sub", getRandomString());
        claims.put("idp", "https://services.bigstate.edu/grid/" + getRandomString());
        return claims;
    }
}
