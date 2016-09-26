package edu.uiuc.ncsa.myproxy.client;

import edu.uiuc.ncsa.security.core.exceptions.InvalidCertRequestException;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;
import junit.framework.TestCase;
import org.junit.Test;

/**   Regression Tests for various cert requests (CSR's).
 * <p>Created by Jeff Gaynor<br>
 * on 5/9/13 at  1:35 PM
 */
public class PKCS10_CSR_Test extends TestCase {
    /**
     * Cert request with a valid subject
     */
    String TEST_WITH_SUBJECT = "MIICVjCCAT4CAQAwETEPMA0GA1UEAwwGaWdub3JlMIIBIjANBgkqhkiG9w0BAQEF\n" +
            "AAOCAQ8AMIIBCgKCAQEAmvZZgw7WDiXJZYsxQvMc+o+2BRk062MFdeQf8N8W+z/A\n" +
            "tyUtXu2UWcHW2TX898ZAoNleBMCe7geSKFs4w+v26VeUOCh1bEE3cH3grE/U5Nt1\n" +
            "RrjM0qyNKB2F4h04nk8fHKLXYl3PaX2gC4WoYroti+wHFnA89mGMJjtuGMQ9wMdH\n" +
            "sj+Cd52g4ZF08EWE27HkhCpJvylEPVVXIcP9ICsXKjO3bjnq2gs/SzUB1enNugD+\n" +
            "dHCsr9V7KKmtSsSUDyz2vbm1nAcuNrlNVzC6GSgG04WNyuwY881eUT6oY2kNqClv\n" +
            "oF//PbgB3RTsyI3/0rw131aZIabGJGE0hxysWR8pVQIDAQABoAAwDQYJKoZIhvcN\n" +
            "AQEFBQADggEBAG21I3LnVcwwkEVqWen2GafHT8tNwkGS7EQGMAIEWZr91bfHkXlI\n" +
            "spayDEuvVBwf1euIxTyRD7PPEH0FHkUbRXa+tYp9vW+nQY2DvXkT8aVAhUUEaa6V\n" +
            "Bb/8mypQovD1JoUvoOXHXweINUb7D1OSXZ3UkXaKzFK5HSaS6cG/QaVbA5CSbfUD\n" +
            "yeckoOFWcV1iZPqXxumBH3298LbPGzrrFtL7283CpGJG1CeOBi0grGqOPUDe/2st\n" +
            "z2IT1KiJQUfCRuYhKTfEX6IePqagtveSTnElbCYOZsIFbzrKnrbtwDzpC7SWd77x\n" +
            "ohGfbITbBDU/9c0GMpItghetvtqcz3W8e+k=\n";


    /**
     * Cert request that has a trivial subject of "/"
     */
    String TEST_NO_SUBJECT = "MIICRTCCAS0CAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALaH\n" +
            "oKW4VCMRfwt1lgisoSMsA5XuEmkFinGbtSUildk4hlvF/6LSkkcOfBZBRsfgIHZv\n" +
            "aX5ppPWSzcXwnY7diN8lgq+o7D9v9qwf878RiONV6o3vti4kjXpGTyRPbbUalSlp\n" +
            "3mS0G2uBO0hwhOKBv4npqHApxEdgNLSPPzyK2OH8biRRhKOe505eZRSVufzEbxGX\n" +
            "OsTJTQfp2mQC34Nc2aPBRmhDm/WVDIKCPCKtzYwGvaP1zWaMCPrwzfOw4b0WKJDr\n" +
            "I+ocgoQOiuOWV6nubw+7R9HzP5YjEaxJQwiyA+0gqhugCZp4iBA6GDdN7KbtXXBz\n" +
            "T4ymCk1cnCypAVa4gtUCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA4IBAQB8dVDM2Xov\n" +
            "Cmt07czxedn6Afb6ldP7wPbfKZ7NwAeD38pex4G1s72USuProLyE49FjLFhvBxZk\n" +
             "fk6KQpZSsWI2wsd5YdgO6F3+kKkSjJaRimkuOgd1wYEdOm1WHQHayJafbjhWiTJ8\n" +
            "OugFWiUzsHnd2Vm77RQDSC00Qk4UGau4N/ww/S4ildGyxCHLVzAW6838aT1Bdqq2\n" +
            "2JS0JvSUq5ymT8o7N6tF8mTDnHPWkotVXDCpjWo8l2Sv59vfVcvY+m7Qp9cPq0+x\n" +
            "ilHSHXnR6Hbwkn/bwy6/O6IzGCUM0ZwchsiWwdlCMm0EcVWWN5tUPg5jmID8mTwX\n" +
            "sjl2GAlxGMZ2";


    /**
     * Bad CR from Globus. This has the version as a zero-length integer. This is needed
     * for the regression test below.
     */
    String BAD_GLOBUS_CR = "MIICRDCCASwCADAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtdf1" +
            "uEiBpLEeJJd16Ed/4Azz8S2jJ6SxqVK+qY74EjwdzMWK+VuIFzZTXJW66hgH2hbn" +
            "cFwTHXs/m/DrEn7yK2tiI3wcjiEQadOKbL8mBTqDGnXHyKyd0KkP0jwN+jVKNm0H" +
            "dEn/rLK+jTInXZZptCbUs3pzEv/Mv2pD0ic5TbyvxjpbZOQpnpQPU/o2Ag46ybjl" +
            "0rsrV4eJok/rE5gn3pLGToHkyzjHYa3cKfdyGszcpzoLXdYKXW9YtlqX1uWsIrHp" +
            "rJkViEkcboGddUTOXE343/CpswRpP2XuAuA65EHDPesPO9HjZxLWvz77pH3R6fgv" +
            "fNWMvPzrRxfuETFcGwIDAQABoAAwDQYJKoZIhvcNAQEFBQADggEBAASns2q27eu1" +
            "162Jce9mVNe0uPqAPCxLMU5h2tbbGO2os0fCd5RmZAZIXIRTRveEzFfHiHe1MKB7" +
            "7l69nFQXub+9RRLtooSChrJndJz+3GJtls051Q0hUkQyV1JX52zQQrEC7mYiBqzk" +
            "cb3OocMa3GnkxfuxL2U/E4wL+IYLxG1SrRoqRL+DB6UPW1giGFGZf2B5KRLQhME+" +
            "GKIho9QtbOjbwmsNCT9VNCEcz0yvp0UYyNzlbMlauOIpsweootEsrbIvFdldvZ2c" +
            "hWArRaD3/75VArvilE32QMRJlz8cddd3Ije7tk3VNMDPELq2Hi+9fUcwL5xtW8QR" +
            "EUeutL3cN/w=";

    /**
     * Cert request made from pyOpenSSL with a version number of zero (which
     * as per spec. really means this is PKCS10 version 1). This should work.
     */
    String GOOD_GLOBUS_CR = "MIICRTCCAS0CAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMM1\n" +
            "OjUH6+CAuJwUjNWjqtIdYc4iPyNFKn2RDnuzl5w0znlrB6JBqG7yuQtrbboJ2lZ/\n" +
            "FayM9VfTYu+IPIrrMI9C29/4Rd9+O4+QqgFl2DiD0TblEpd/ub6pqCRGHv+rgT7z\n" +
            "LG/xJYrWFjoSfilToOT6NHAoHkQP1V1I2t/TW2YqQBS61EbhX2zci+8ctnYBQBTR\n" +
            "nNSyTMYqwpUSux7kVZp0yIr7udo4izA/maTd7ab3hQpaX+4P9ue18fcx5gqhG/CA\n" +
            "kFoqIvWBXOdzC3dJLICR3VOLcC5S8Yt9z9SQ8bNpB6mYYZikte5+70Qy+kKpZB8r\n" +
            "ufEbNw1PmxCb4IBmsy8CAwEAAaAAMA0GCSqGSIb3DQEBBQUAA4IBAQCc7+rbfGPz\n" +
            "oP1WGe1AeUKYODmpSAp1dEzbMyfjccseT3x7WKlUJELUEcWwu95D4BZn+F9DClhJ\n" +
            "JP+sCdMkWS+LTha+F3ezah/5Htie9Usu3deWmGnZa7FNw0QFYKw3WWGT+HXpVeAK\n" +
            "Tmy0mJ/GqoRzGc7RBJy1mK1qzs09A1Ko1vJVgnUQQZ098QGFewt/aQ3QJaVvGFwZ\n" +
            "gAB40svp+oCDBguJ2MAdRo6m8klY0IWmg+hwpycW0z/Mk7gP/kYz0CeMzT5TQ/Mn\n" +
            "78lx7Y0ujC6umb7gMnHZ5MQMYNsjPs7sLH3MqeR2dlL7dx0TEHsHeCT+sUt2Wik0\n" +
            "blpsel1Ayyew\n";

    @Test
    public void testSubjects() throws Exception {
        MyPKCS10CertRequest certReq = CertUtil.fromStringToCertReq(GOOD_GLOBUS_CR);
        assert certReq.getPublicKey() != null;

        certReq = CertUtil.fromStringToCertReq(TEST_WITH_SUBJECT);
        assert certReq.getPublicKey() != null;

        certReq = CertUtil.fromStringToCertReq(TEST_NO_SUBJECT);
        assert certReq.getPublicKey() != null;


    }

    @Test
    public void testBadCSR() throws Exception {
        try {
            MyPKCS10CertRequest certReq = CertUtil.fromStringToCertReq(BAD_GLOBUS_CR);
            System.out.println(certReq.getPublicKey());
            assert false : "Was able to process a bad cert request.";
        } catch (InvalidCertRequestException iox) {
            assert true;
        }

        try {
            MyPKCS10CertRequest certReq = CertUtil.fromStringToCertReq(GOOD_GLOBUS_CR);
            assert certReq.getPublicKey() != null;
        } catch (InvalidCertRequestException iox) {
            iox.printStackTrace();
            assert false : "Good cert request failed to parse correctly.";
        }
    }
}
