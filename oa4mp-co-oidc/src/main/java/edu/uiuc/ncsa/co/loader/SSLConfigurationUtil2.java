package edu.uiuc.ncsa.co.loader;

import edu.uiuc.ncsa.security.delegation.storage.JSONUtil;
import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;
import edu.uiuc.ncsa.security.util.ssl.SSLConfigurationUtil;
import net.sf.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/15/16 at  10:17 AM
 */
public class SSLConfigurationUtil2 extends SSLConfigurationUtil {
    public static JSONObject toJSON(SSLConfiguration sslConfiguration) {
        JSONObject ssl = new JSONObject();
        JSONUtil jsonUtil = getJSONUtil();
        JSONObject content = new JSONObject();
        JSONObject keyStore = new JSONObject();
        content.put(SSL_KEYSTORE_TAG, keyStore);
        ssl.put(SSL_TAG, content);

        jsonUtil.setJSONValue(ssl, SSL_TLS_VERSION_TAG, sslConfiguration.getTlsVersion());
        jsonUtil.setJSONValue(ssl, SSL_TRUSTSTORE_USE_JAVA_TRUSTSTORE, sslConfiguration.isUseDefaultJavaTrustStore());
        jsonUtil.setJSONValue(ssl, SSL_KEYSTORE_PASSWORD, sslConfiguration.getKeystorePassword());
        jsonUtil.setJSONValue(ssl, SSL_KEYSTORE_TYPE, sslConfiguration.getKeystoreType());
        byte[] keystore = null;
        try {
            InputStream is = sslConfiguration.getKeystoreIS();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            int nRead;
            byte[] data = new byte[16384];

            while ((nRead = is.read(data, 0, data.length)) != -1) {
                baos.write(data, 0, nRead);
            }

            baos.flush();
            keystore = baos.toByteArray();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        if(keystore != null){
           jsonUtil.setJSONValue(ssl, SSL_KEYSTORE_TAG, org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(keystore));
        }
        return ssl;
    }

    public static SSLConfiguration fromJSON(JSONObject json) {
        SSLConfiguration ssl = new SSLConfiguration();
        JSONUtil jsonUtil = getJSONUtil();
        ssl.setTlsVersion(jsonUtil.getJSONValueString(json, SSL_TLS_VERSION_TAG));
        ssl.setKeystoreType(jsonUtil.getJSONValueString(json, SSL_KEYSTORE_TYPE));
        ssl.setKeystorePassword(jsonUtil.getJSONValueString(json, SSL_KEYSTORE_PASSWORD));
        ssl.setUseDefaultJavaTrustStore(jsonUtil.getJSONValueBoolean(json,SSL_TRUSTSTORE_USE_JAVA_TRUSTSTORE));
        ssl.setKeystoreBytes(org.apache.commons.codec.binary.Base64.decodeBase64(jsonUtil.getJSONValueString(json, SSL_KEYSTORE_TAG)));
        // JSON does not have a concept of a path to a local file. The keystore value is the base 64 encoding of a file
        // to be used. The SSLConfig object, however, puts in a default value for the keystore path if the
        // use java option is enabled.
        if(!ssl.isUseDefaultJavaTrustStore()) {
            ssl.setKeystore(null);
        }
        return ssl;
    }

    public static JSONUtil getJSONUtil() {
        if (jsonUtil == null) {
            jsonUtil = new JSONUtil(SSL_TAG);
        }
        return jsonUtil;
    }

    static JSONUtil jsonUtil = null;

}
