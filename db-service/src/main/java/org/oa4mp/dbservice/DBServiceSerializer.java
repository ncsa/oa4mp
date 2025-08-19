package org.oa4mp.dbservice;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import net.sf.json.JSONObject;
import org.oa4mp.delegation.common.storage.clients.ClientApprovalKeys;
import org.oa4mp.delegation.common.storage.clients.ClientKeys;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;

import java.io.*;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Date;
import java.util.Map;

import static org.oa4mp.dbservice.DBService.STATUS_KEY;


/**
 * A class that serializes to a print writer or deserializes to streams.
 * <p>Created by Jeff Gaynor<br>
 * on Nov 19, 2010 at  11:03:15 AM
 */
public class DBServiceSerializer {
    public DBServiceSerializer(
                               ClientKeys cKeys,
                               ClientApprovalKeys caKeys) {
        this.clientKeys = cKeys;
        this.clientApprovalKeys = caKeys;
    }

    public final static String CILOGON_SUCCESS_URI = "cilogon_success";
    public final static String CILOGON_FAILURE_URI = "cilogon_failure";
    public final static String CILOGON_PORTAL_NAME = "cilogon_portal_name";
    public final static String CILOGON_CALLBACK_URI = "cilogon_callback";
    public static final String UTF8_ENCODING = "UTF-8"; // character encoding

    protected ClientKeys clientKeys;
    protected ClientApprovalKeys clientApprovalKeys;

    public void writeMessage(PrintWriter w, String message) throws IOException {
        print(w, STATUS_KEY, message);
    }


    public void writeMessage(PrintWriter w, int statusCode) throws IOException {
        print(w, STATUS_KEY, Integer.toString(statusCode));
    }

    public void serialize(PrintWriter w, Map<String, Object> map) throws IOException {
        writeMessage(w, map.get(STATUS_KEY).toString());
        for (String k : map.keySet()) {
            if (!k.equals(STATUS_KEY)) {
                print(w, k, map.get(k).toString());
            }
        }
    }


    protected void onlyPrintIfNotTrivial(PrintWriter w, String key, String value) throws IOException {
        if (value != null && !value.isEmpty()) {
            print(w, key, value);
        }
    }


    /**
     * This takes the serialized payload and pulls it into a simple map. This is mostly
     * used to deserialize things that might not be available to a client, such as a
     * server transaction.
     * <h3>Caveats</h3>
     * <UL>
     * <LI>The status is always stored as a Long</LI>
     * <LI>List values are stored as List&lt;String&gt;'s</LI>
     * <LI>This never throws an exception if there is an issue. You must decide on the course
     * of action from the returned status code.</LI>
     * </UL>
     *
     * @param is
     * @return
     * @throws IOException
     */
 /*   public XMLMap deserializeToMap(InputStream is) throws IOException {
        XMLMap buffer = new XMLMap();
        BufferedReader br = new BufferedReader(new InputStreamReader(is));
        String linein = br.readLine();
        List<IdentityProvider> idps = null; // just in case it's needed
        if (linein == null || linein.length() == 0) {
            throw new NFWException("Error: service returned a trivial string. This means the service is not responding to requests correctly.");
        }

        try {
            while (linein != null) {
                String[] headAndTail = parseLine(linein);
                if (headAndTail[0].equals(idpKeys.identifier())) {
                    if (idps == null) {
                        idps = new LinkedList<IdentityProvider>();
                        buffer.put(headAndTail[0], idps);
                    }
                    idps.add(new IdentityProvider(BasicIdentifier.newID(headAndTail[1])));
                } else if (headAndTail[0].equals(AbstractDBService.STATUS_KEY)) {
                    buffer.put(headAndTail[0], Long.parseLong(headAndTail[1]));
                } else {
                    buffer.put(headAndTail[0], headAndTail[1]);
                }
                linein = br.readLine();
            }
        } finally {
            br.close();
        }
        return buffer;
    }*/

    /**
     * Checks that the serialized content of the input stream has an ok as its status. This
     * <b>ignores</b> the rest of the stream and discards it! Only use when you are sure there
     * is nothing else to parse, but want to check that an operation worked. If there are other
     * status codes, this will throw an exception corresponding to the error.
     *
     * @param is
     * @return
     * @throws Exception
     */
    public boolean reponseOk(InputStream is) throws IOException {
        return readResponseOnly(is) % 2 == 0;
    }

    public int readResponseOnly(InputStream is) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(is));
        String linein = br.readLine();
        String[] x = splitLine(linein);
        br.close();
        try {
            return Integer.parseInt(x[1]);
        } catch (NumberFormatException nfx) {
            throw new GeneralException("Error: unparseable response: " + linein, nfx);
        }
    }




    protected String[] splitLine(String linein) throws UnsupportedEncodingException {
        int pos = linein.indexOf("=");
        String head = linein.substring(0, pos);
        String tail = decode(linein.substring(pos + 1));
        return new String[]{head, tail};

    }

    protected String[] parseLine(String linein) throws UnsupportedEncodingException {
        String[] x = splitLine(linein);
        checkForStatus(x[0], x[1]);
        return x;
    }

    /**
     * Checks the status line in the serialized object for error codes and throws a corresponding
     * exception. If the status is ok, the call succeeds.
     *
     * @param head
     * @param tail
     */
    protected void checkForStatus(String head, String tail) {
        if (head.equals(STATUS_KEY)) {
            // Even return  codes are ok and informational.
            if (Integer.parseInt(tail) % 2 == 0) return;
            ServletDebugUtil.trace(this, "Got unrecognized response of head=\"" + head + "\" tail=\"" + tail + "\"");
            throw new DBServiceException(tail);
        }
    }


    protected String encode(String x) throws UnsupportedEncodingException {
        return URLEncoder.encode(x, UTF8_ENCODING);
    }

    protected String encode(URI x) throws UnsupportedEncodingException {
        return encode(x.toString());
    }

    public String decode(String x) throws UnsupportedEncodingException {
        return URLDecoder.decode(x, UTF8_ENCODING);
    }

    protected void print(PrintWriter w, String key, Identifier identifier) throws IOException {
        print(w, key, identifier == null ? "" : identifier.toString());
    }

    protected void print(PrintWriter w, String key, URI uri) throws IOException {
        print(w, key, uri == null ? "" : uri.toString());
    }

    protected void print(PrintWriter w, String key, Date date) throws IOException {
        print(w, key, Iso8601.date2String(date));
    }

    public void print(PrintWriter w, String key, String value) throws IOException {
        w.println(key + "=" + (value == null ? "" : encode(value)));
    }

    public void print(PrintWriter w, String key, Object value) throws IOException {
        w.println(key + "=" + (value == null ? "" : encode(value.toString())));
    }

    public void serialize(PrintWriter w, OA2ServiceTransaction oa2ServiceTransaction, int status) throws IOException {
        writeMessage(w, status);
    }

    public void serialize(PrintWriter w, OA2ServiceTransaction oa2ServiceTransaction, Err errResponse) throws IOException {
        writeMessage(w, errResponse);
    }
    public void writeMessage(PrintWriter w, Err errResponse) throws IOException {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(STATUS_KEY, errResponse.code);
        jsonObject.put("error", errResponse.error);
        jsonObject.put("description", errResponse.description);
        // CIL-1187 support.
        // CIL-1388,  CIL-1342
        if(errResponse.customErrorURI != null) {
            jsonObject.put("custom_error_uri", errResponse.customErrorURI.toString());
        }
        if(errResponse.errorURI != null) {
            jsonObject.put("error_uri", errResponse.errorURI.toString());
        }
        w.println(jsonObject);
    }
   /* public void writeMessage(PrintWriter w, Err errResponse) throws IOException {
        writeMessage(w, errResponse.code);
        print(w, "error", errResponse.error);
        print(w, "error_description", errResponse.description);
        // CIL-1187 support.
        // CIL-1388,  CIL-1342
        if(errResponse.customErrorURI != null) {
            print(w, "custom_error_uri", errResponse.customErrorURI.toString());
        }
        if(errResponse.errorURI != null) {
            print(w, "error_uri", errResponse.errorURI.toString());
        }
    }*/
  }
