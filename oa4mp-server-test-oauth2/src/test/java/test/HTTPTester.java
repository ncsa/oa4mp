package test;

import edu.uiuc.ncsa.security.util.TestBase;
import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;
import edu.uiuc.ncsa.security.util.ssl.VerifyingHTTPClientFactory;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.*;

import java.io.IOException;

/**
 * This class is the top-level class for running tests against an http endpoint. It assumes that
 * there are properties for the address and credentials.
 * <p>Created by Jeff Gaynor<br>
 * on 10/17/19 at  11:02 AM
 */
public class HTTPTester extends TestBase {
    VerifyingHTTPClientFactory vcf;

    protected String getSecret() {
        return System.getProperty("clientSecret");
    }

    protected String getID() {
        return System.getProperty("clientID");

    }

    protected String getAddress() {
        return System.getProperty("serverAddress");

    }

    VerifyingHTTPClientFactory getVCF() throws IOException {
        if (vcf == null) {
            vcf = new VerifyingHTTPClientFactory(null, new SSLConfiguration());
        }
        return vcf;
    }


    protected HttpResponse doRequest(HttpUriRequest request) throws IOException {
        HttpClient client = newClient();
        return client.execute(request);

    }

    protected String createCreds() {
        String creds = getID() + ":" + getSecret();
        return Base64.encodeBase64URLSafeString(creds.getBytes());

    }

    protected HttpResponse doDelete() throws IOException {
        HttpDelete deleteReq = new HttpDelete(getAddress());
        deleteReq.setHeader("Authorization: Bearer", createCreds());
        return doRequest(deleteReq);
    }


    protected HttpResponse doGet() throws IOException {
        HttpGet getReq = new HttpGet(getAddress());
        getReq.setHeader("Authorization: Bearer", createCreds());
        return doRequest(getReq);
    }


    protected HttpResponse doPut() throws IOException {
        HttpPut putReq = new HttpPut(getAddress());
        putReq.setHeader("Authorization: Bearer", createCreds());
        putReq.setHeader("Content-Type", "application/json; charset=UTF-8");
        return doRequest(putReq);
    }

    protected HttpResponse doPost() throws IOException {
        HttpPost postReq = new HttpPost(getAddress());
        postReq.setHeader("Authorization: Bearer", createCreds());
        postReq.setHeader("Content-Type", "application/json; charset=UTF-8");
        return doRequest(postReq);
    }

    protected HttpClient newClient() throws IOException {
        HttpClient client = vcf.getClient(getAddress());
        return client;
    }
}
