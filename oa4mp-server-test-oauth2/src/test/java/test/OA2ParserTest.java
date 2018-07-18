package test;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.FunctorClaimsType;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2FunctorFactory;
import edu.uiuc.ncsa.security.util.FunctorParserTest;
import edu.uiuc.ncsa.security.util.functor.JFunctorFactory;
import edu.uiuc.ncsa.security.util.functor.parser.event.EDLBSHandler;
import edu.uiuc.ncsa.security.util.functor.parser.event.EventDrivenFunctorHandler;
import edu.uiuc.ncsa.security.util.functor.parser.event.EventDrivenLogicBlockHandler;
import edu.uiuc.ncsa.security.util.functor.parser.event.EventDrivenParser;
import org.junit.Test;

import java.util.Map;

import static test.OA2FunctorTests.GROUP_NAME;
import static test.OA2FunctorTests.createClaims;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/17/18 at  8:40 AM
 */
public class OA2ParserTest extends FunctorParserTest {
    protected OA2FunctorFactory createOA2FF(Map<String, Object> claims) {
        return (OA2FunctorFactory) createFunctorFactory(claims);
    }

    @Override
    protected JFunctorFactory createFunctorFactory(Object claims) {
        return new OA2FunctorFactory((Map<String, Object>) claims);
    }

    /**
     * tests that the isMemberOf functor works against the claims. Here the test is against membership in a single
     * group.
     *
     * @throws Exception
     */
    @Test
    public void testIsMemberOf() throws Exception {
        Map<String, Object> claims = createClaims();
        OA2FunctorFactory ff = createOA2FF(claims);
        String testString = "isMemberOf(\"" + GROUP_NAME + "2\")";
        EventDrivenParser eventDrivenParser = new EventDrivenParser();
        EventDrivenFunctorHandler eventDrivenFunctorHandler = new EventDrivenFunctorHandler(ff);
        eventDrivenParser.addParenthesisListener(eventDrivenFunctorHandler);
        eventDrivenParser.addDoubleQuoteListener(eventDrivenFunctorHandler);
        eventDrivenParser.addCommaListener(eventDrivenFunctorHandler);
        eventDrivenParser.parse(testString);
        eventDrivenFunctorHandler.getFunctor().execute();
        assert (Boolean) eventDrivenFunctorHandler.getFunctor().getResult();


    }

    /**
     * Test that setting the eppn then specifying a replacement works.
     *
     * @throws Exception
     */
    @Test
    public void testEPPN() throws Exception {


        String testString = "" +
                " or{" +
                "   if[" +
                "      and(" +
                "          endsWith(get(\"eppn\"),\"@ncsa.illinois.edu\")," +
                "         contains(\"foo\",\"zfoo\")" +
                "        )" +
                "     ]then[" +
                "      set(\"eppn\",\"test:eppn/1\")" +
                "     ]," +
                "   if[" +
                "    and(" +
                "        contains(\"foo\",\"zfoo\")," +
                "       endsWith(get(\"eppn\"),\"@illinois.edu\")" +
                "      )" +
                "    ]then[" +
                "  set(\"eppn\",\"test:eppn/2\")" +
                "   ]" +
                " }";
        // All this should result in the string "pq"
        Map<String, Object> claims = createClaims();
        claims.put("eppn", "jgaynor@ncsa.illinois.edu");

        EventDrivenParser parser = new EventDrivenParser();
        JFunctorFactory functorFactory = createFunctorFactory(claims);
        EventDrivenFunctorHandler fh = new EventDrivenFunctorHandler(functorFactory);
        EventDrivenLogicBlockHandler lbh = new EventDrivenLogicBlockHandler(fh, functorFactory);
        EDLBSHandler eh = new EDLBSHandler(lbh, functorFactory);
        parser.addBraceListener(eh);
        parser.addCommaListener(eh);
        parser.parse(testString);
        eh.getLogicBlocks().execute();
        System.out.println(eh.getLogicBlocks().getFunctorMap());
        System.out.println(claims);
        assert claims.get("eppn").equals("test:eppn/1");
        assert eh.getLogicBlocks().getFunctorMap().containsKey(FunctorClaimsType.SET.getValue());


    }

    @Test
    public void testLSST() throws Exception{
        assert doLSST(OA2FunctorTests.EPPN,null,null,null).equals(OA2FunctorTests.EPPN);
        assert doLSST(null,OA2FunctorTests.EPTID,null,null).equals(OA2FunctorTests.EPTID);
        assert doLSST(null,null,OA2FunctorTests.oidc,OA2FunctorTests.GITHUB_IDP).equals(OA2FunctorTests.oidc +"@github.com");
        assert doLSST(null,null,OA2FunctorTests.oidc,OA2FunctorTests.GOOGLE_IDP).equals(OA2FunctorTests.oidc +"@accounts.google.com");
        assert doLSST(null,null,OA2FunctorTests.orcid,OA2FunctorTests.ORCID_IDP).equals(OA2FunctorTests.orcid.replace("http://", "https://"));
    }

    protected String doLSST(String eppn, String eptid, String oidc, String idp) {
        String testString = "xor{" +
                "if[hasClaim(\"eppn\")]then[set(\"voPersonExternalID\",get(\"eppn\"))]," +
                "if[hasClaim(\"eptid\")]then[set(\"voPersonExternalID\",get(\"eptid\"))]," +
                "if[equals(get(\"idp\"),\"http://github.com/login/oauth/authorize\")]then[set(\"voPersonExternalID\",concat(get(\"oidc\"),\"@github.com\"))]," +
                "if[equals(get(\"idp\"),\"http://google.com/accounts/o8/id\")]then[set(\"voPersonExternalID\",concat(get(\"oidc\"),\"@accounts.google.com\"))]," +
                "if[equals(get(\"idp\"),\"http://orcid.org/oauth/authorize\")]then[set(\"voPersonExternalID\",replace(get(\"oidc\"),\"http://\",\"https://\"))]" +
                "}";

        Map<String, Object> claims = createClaims();
        if (eppn != null) {
            claims.put("eppn", eppn);
        }
        if (eptid != null) {
            claims.put("eptid", eptid);
        }
        if (oidc != null) {
            claims.put("oidc", oidc);
        }
        if (idp != null) {
            claims.put("idp", idp);
        }

        EventDrivenParser parser = new EventDrivenParser();
        JFunctorFactory functorFactory = createFunctorFactory(claims);
        EventDrivenFunctorHandler fh = new EventDrivenFunctorHandler(functorFactory);
        EventDrivenLogicBlockHandler lbh = new EventDrivenLogicBlockHandler(fh, functorFactory);
        EDLBSHandler eh = new EDLBSHandler(lbh, functorFactory);
        parser.addBraceListener(eh);
        parser.addCommaListener(eh);
        parser.parse(testString);
        eh.getLogicBlocks().execute();
        System.out.println(eh.getLogicBlocks().getFunctorMap());
        System.out.println(claims);
        System.out.println("voPersonExternalID= " + claims.get("voPersonExternalID").toString());
        return claims.get("voPersonExternalID").toString();

    }

    @Test
    public void testVOPerson() throws Exception {
        String rawJSON = ":{\"$or\":[{\"$if\":[{\"$hasClaim\":[\"eppn\"]}],\"$then\":[{\"$set\":[\"voPersonExternalID\",{\"$get\":[\"eppn\"]}]}]},{\"$if\":[{\"$hasClaim\":[\"eptid\"]}],\"$then\":[{\"$set\":[\"voPersonExternalID\",{\"$get\":[\"eptid\"]}]}]}," +
                "{\"$if\":[{\"$equals\":[{\"$get\":[\"idp\"]},\"http://github.com/login/oauth/authorize\"]}]," +
                "\"$then\":[{\"$set\":[\"voPersonExternalID\"," +
                "{\"$concat\":[{\"$get\":[\"oidc\"]},\"@github.com\"]}]}]},{\"$if\":[{\"$equals\":[{\"$get\":[\"idp\"]}," +
                "\"http://google.com/accounts/o8/id\"]}],\"$then\":[{\"$set\":[\"voPersonExternalID\",{\"$concat\":[{\"$get\":[\"oidc\"]},\"@accounts.google.com\"]}]}]},{\"$if\":[{\"$equals\":" +
                "[{\"$get\":[\"idp\"]},\"http://orcid.org/oauth/authorize\"]}],\"$then\":[{\"$set\":[\"voPersonExternalID\",{\"$replace\":[{\"$get\":[\"oidc\"]},\"http://\",\"https://\"]}]}]}]}";
        String testString = "xor{" +
                "if[hasClaim(\"eppn\")]then[set(\"voPersonExternalID\",get(\"eppn\"))]," +
                "if[hasClaim(\"eptid\")]then[set(\"voPersonExternalID\",get(\"eptid\"))]," +
                "if[equals(get(\"idp\"),\"http://github.com/login/oauth/authorize\")]then[set(\"voPersonExternalID\",concat(get(\"oidc\"),\"@github.com\"))]," +
                "if[equals(get(\"idp\"),\"http://google.com/accounts/o8/id\")]then[set(\"voPersonExternalID\",concat(get(\"oidc\"),\"@accounts.google.com\"))]," +
                "if[equals(get(\"idp\"),\"http://orcid.org/oauth/authorize\")]then[set(\"voPersonExternalID\",replace(get(\"oidc\"),\"http://\",\"https://\"))]" +
                "}";

        Map<String, Object> claims = createClaims();
        claims.put("eppn", "jgaynor@ncsa.illinois.edu");

        EventDrivenParser parser = new EventDrivenParser();
        JFunctorFactory functorFactory = createFunctorFactory(claims);
        EventDrivenFunctorHandler fh = new EventDrivenFunctorHandler(functorFactory);
        EventDrivenLogicBlockHandler lbh = new EventDrivenLogicBlockHandler(fh, functorFactory);
        EDLBSHandler eh = new EDLBSHandler(lbh, functorFactory);
        parser.addBraceListener(eh);
        parser.addCommaListener(eh);
        parser.parse(testString);
        eh.getLogicBlocks().execute();
        System.out.println(eh.getLogicBlocks().getFunctorMap());
        System.out.println(claims);
        assert claims.get("voPersonExternalID").equals("jgaynor@ncsa.illinois.edu");
        assert eh.getLogicBlocks().getFunctorMap().containsKey(FunctorClaimsType.SET.getValue());
    }
}
