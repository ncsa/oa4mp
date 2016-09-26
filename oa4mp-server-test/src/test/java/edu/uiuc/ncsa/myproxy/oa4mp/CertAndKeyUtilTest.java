package edu.uiuc.ncsa.myproxy.oa4mp;

import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;
import edu.uiuc.ncsa.security.util.pkcs.PEMFormatUtil;
import junit.framework.TestCase;
import org.junit.Test;

import java.io.File;
import java.io.FileReader;
import java.io.StringWriter;
import java.net.URL;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

/**
 * Test the cert and key utils
 * <p>Created by Jeff Gaynor<br>
 * on Jun 15, 2010 at  5:03:32 PM
 */
public class CertAndKeyUtilTest extends TestCase {
    @Test
    public void testDecode() throws Exception {
        String req = "MIICwTCCAakCAQAwfDELMAkGA1UEBhMCVVMxETAPBgNVBAgMCElsbGlub2lzMRAwDgYDVQQHDAdBcmdvbm5lMRAwDgYDVQQKDAdBcmdvbm5lMRQwEgYDVQQDDAtUaG9tYXMgVXJhbTEgMB4GCSqGSIb3DQEJARYRdHVyYW1AbWNzLmFubC5nb3YwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDDofjHElcWlaffUDg2nM/vFojXnLIMAjqlKOXdF0XToFWwnR/3ZtlpmAUW1A1L1l7UJLWYEZvtp0OIt/tcyhIWrU+uiu8LVFtZxhZwz90pCyWycsZ+54aVU3VhfgIEPzX49Xdkt/IvdDHCejL5YS0sGGYBP8gw6/hLCQLMz0PFi/xShJupqM7hmUP6uVBSEXgoMTBlquLZKl7vn0GTB0xM9Zmi2T1Td7fKU49UVmJqNS61dTVohaGsATBAL08rOouY5nQj1xMQgdmMlWOcZ2nCG00ztDWrmz2879odb3YKgdw5fAOMkDClUPvbF4Le+cplDpStdpk5JL1AX38BqFjnAgMBAAGgADANBgkqhkiG9w0BAQUFAAOCAQEASX3RbyPOnlksWlbMpaJGi1hJFFdKWisW7aIeZiSQES4tEZV1fTt3kbXSTKxOptUbqiMmi8VvVJktY6RsSPXdGGqFQqXnYZyX0OWfDX3qwQHmYWx6UzD3hDwJhDYQMl+L/iI1dq4fO46OqAf9t8sFX8LYuBiA4hjSVZZ/vewTu2lLhTqK0iEcJ6m1B+FQ2NSFEmNKWkFqtO0UnIhhBsCS3Ym0zyjIWwr/8lDpYTow8LChOTwkHJdhN/EOvCg1Tp2R5u35dJGADZ+/OPyQzvox/OZ5x5IX9Nby8iCGt9dp3gBliB3mbZ5be80QQhbnkO/fuj0rTuzeodkwkMjGlaVGdA==";
        String req3 = "MIICwDCCAagCAQAwezELMAkGA1UEBhMCVVMxETAPBgNVBAgMCElsbGlub2lzMRAwDgYDVQQHDAdBcmdvbm5lMRAwDgYDVQQKDAdBcmdvbm5lMRMwEQYDVQQDDApUaG9tYXNVcmFtMSAwHgYJKoZIhvcNAQkBFhF0dXJhbUBtY3MuYW5sLmdvdjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANkQfpWUt/3l4SNoRRN8JicdCjX5RHmIzYujTea82B05M/9VGU6vsPD9afEI2GjX8Q/vmjGVs+w+QzGOu59+vmCiAAKWwUiw7Qr4Uk0kOe+z4RSLh1E7wXk4Mqh+PeF+rysmL6r5dhNlvyr/tF0LCZ3qkWgW42U9/od5uftEtSyRIvkbVnIDJPzSeD/Rj173d9WRXaTSML0VK9euJAr/12V4kV9k3pmCKk/7qMPQfjpyfTnrdc4orvIW5HWDnAGUWgzFXDvFyhrYo0QzgmfbeuLR0PQTQwpTyhBdbUrc5cqjG1gveybSXMB7sbHJVbWSUH80VlP+GXTeL8rObZzCgI8CAwEAAaAAMA0GCSqGSIb3DQEBBQUAA4IBAQCs/uc1PdHaEe/gfkwKgPpvuOj2rn6hIiWC4tpF4N/ROP5jRA3YXXnR5SEQZwfAgmSuX9qfAeg5eA0MEqav4nLl97gsvCpojh1aX0TYRcmQIL5A1Y988mANiFDDwZJzj241XJSQTB8owy7d5WxnaGL2WYnElKqWfag6CdA9e6/6mO3BjG7aGXpeYHQmD1VPLLrm2TIchg5UDG+/l/mnpwaiaqlXEHtL/tu6BrpomPVhnL3vwWhgpdeZuIzcw4KPXO8Y7E+mXmn/jAKAJh3vW6Li1XYgw80EFzPek56FaracatI6k50lA7pBf6bto9XXDK2SiMP7DEp57rSVMXciwTZ9";
        // These cert requests are made in a few ways. Just checks that all get decoded right.
        CertUtil.fromStringToCertReq(req);
        CertUtil.fromStringToCertReq(req3);
    }

    @Test
    public void testKeyGeneration() throws Exception {

        KeyPair keypair = KeyUtil.generateKeyPair();
        // test encoding and decoding.
        byte[] encodedPrivate = KeyUtil.privateToDER(keypair);

        PrivateKey privKey = KeyUtil.fromPKCS8DER(encodedPrivate);
        assert privKey.equals(keypair.getPrivate());

        byte[] encodedPublic = KeyUtil.publicToDER(keypair);
        PublicKey pubKey = KeyUtil.fromX509DER(encodedPublic);
        assert pubKey.equals(keypair.getPublic());
    }

    @Test
    public void testCertReq() throws Exception {
        KeyPair keyPair = KeyUtil.generateKeyPair();
        // Can't really do much to check. If it completes though we are in the ballpark.
        System.out.println("Public key:\n" + KeyUtil.toX509PEM(keyPair.getPublic()));
        System.out.println("Private key:\n" + KeyUtil.toPKCS8PEM(keyPair.getPrivate()));
        MyPKCS10CertRequest cr = CertUtil.createCertRequest(keyPair);
        System.out.println("Cert request:\n" + cr);
        assert true;
    }


    protected String readFile(String fileName)
            throws java.io.IOException {
        URL url = this.getClass().getResource("/" + fileName);
        File f = new File(url.getFile());
        return PEMFormatUtil.readerToString(new FileReader(f));
    }

    @Test
    public void testCertPEM() throws Exception {
        String cert = readFile("test-cert.pem");
        X509Certificate[] certificate = CertUtil.fromX509PEM(cert);
        assert certificate.length == 1 : "Error, incorrect number of certs returned (should be 1, got" + certificate.length + ")";
        assert certificate[0].getSubjectDN() != null; // so it worked
    }

    @Test
    public void testX509PublicKey() throws Exception {
        // Read in a public key made someplace else (OpenSSL, actually).
        String puk = readFile("public-key.pem");
        PublicKey puk2 = KeyUtil.fromX509PEM(puk);
        // So since we have one, encoded it again and test it against the existing decoding.
        String puk3 = KeyUtil.toX509PEM(puk2);
        assert puk2.equals(KeyUtil.fromX509PEM(puk3));
    }

    @Test
    public void testPKCS8Key() throws Exception {
        // show we can read a good one
        String keyFile = readFile("private-key.pk8");
        PrivateKey prk = KeyUtil.fromPKCS8PEM(keyFile);
        assert true; // won't get here unless it parses it right.
        // show we can write one, then read it.
        StringWriter sw = new StringWriter();
        // and test the writer call too
        KeyUtil.toPKCS8PEM(prk, sw);
        assert KeyUtil.fromPKCS8PEM(sw.getBuffer().toString()).equals(prk);
    }
}
