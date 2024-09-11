package org.oa4mp.delegation.server.server.config;

import org.oa4mp.delegation.common.storage.JSONUtil;
import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;
import edu.uiuc.ncsa.security.util.ssl.SSLConfigurationUtil;
import net.sf.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/16 at  3:03 PM
 */
public class SSLConfigurationUtil2 extends SSLConfigurationUtil {
    public static JSONObject toJSON(SSLConfiguration sslConfiguration) {
        try {
            return toJSONNEW(sslConfiguration);
        } catch (Throwable t) {
            return toJSONOLD(sslConfiguration);
        }
    }

    protected static JSONObject toJSONNEW(SSLConfiguration sslConfiguration) {
        JSONObject output = new JSONObject();
        JSONObject trustStore = new JSONObject();
        JSONObject keyStore = new JSONObject();
        output.put(SSL_TLS_VERSION_TAG, sslConfiguration.getTlsVersion());
        if (sslConfiguration.getKeystore() != null) {
            keyStore.put(SSL_KEYSTORE_PATH, sslConfiguration.getKeystore());
        }
        if (sslConfiguration.getKeystoreType() != null) {
            keyStore.put(SSL_KEYSTORE_TYPE, sslConfiguration.getKeystoreType());
        }
    
        if(sslConfiguration.getKeystorePassword() != null){
            keyStore.put(SSL_KEYSTORE_PASSWORD, sslConfiguration.getKeystorePassword());
        }
        if (!keyStore.isEmpty()) {
            output.put(SSL_KEYSTORE_TAG, keyStore);
        }
        // Now for the trust store -- this always has a trust store, even if it is trivially the one with Java
        trustStore.put(SSL_TRUSTSTORE_USE_JAVA_TRUSTSTORE, sslConfiguration.isUseDefaultJavaTrustStore());
        trustStore.put(SSL_TRUSTSTORE_IS_STRICT_HOSTNAMES, sslConfiguration.isStrictHostnames());
        trustStore.put(SSL_TRUSTSTORE_USE_DEFAULT_TRUST_MANAGER, sslConfiguration.isUseDefaultTrustManager());

        if (sslConfiguration.getTrustRootPassword() != null) {
            trustStore.put(SSL_TRUSTSTORE_PASSWORD, sslConfiguration.getTrustRootPassword());
        }
        if (sslConfiguration.getKeystoreType() != null) {
            trustStore.put(SSL_TRUSTSTORE_TYPE, sslConfiguration.getTrustRootType());
        }
        if (sslConfiguration.getTrustrootPath() != null) {
            trustStore.put(SSL_TRUSTSTORE_PATH, sslConfiguration.getTrustrootPath());
        }
        if (sslConfiguration.getTrustRootCertDN() != null) {
            trustStore.put(SSL_TRUSTSTORE_CERTIFICATE_DN, sslConfiguration.getTrustRootCertDN());
        }
        output.put(SSL_TRUSTSTORE_TAG, trustStore);
        return output;
    }

    /*
               if (keyStoreNode != null) {
                // keystore is optional. Only process if there is one.
                sslConfiguration.setKeystore(getNodeValue(keyStoreNode, SSL_KEYSTORE_PATH));
                sslConfiguration.setKeystorePassword(getNodeValue(keyStoreNode, SSL_KEYSTORE_PASSWORD));
                sslConfiguration.setKeyManagerFactory(getNodeValue(keyStoreNode, SSL_KEYSTORE_FACTORY));
                sslConfiguration.setKeystoreType(getNodeValue(keyStoreNode, SSL_KEYSTORE_TYPE));
            }


            // If they want to use the default trust manager, don't read any other
            // trust manager configuration, just return
            ConfigurationNode trustStoreNode = getFirstNode(node, SSL_TRUSTSTORE_TAG);
            if (trustStoreNode != null) {
                sslConfiguration.setTrustRootPath(getNodeValue(trustStoreNode, SSL_TRUSTSTORE_PATH));
                sslConfiguration.setTrustRootPassword(getNodeValue(trustStoreNode, SSL_TRUSTSTORE_PASSWORD));
                sslConfiguration.setTrustRootType(getNodeValue(trustStoreNode, SSL_TRUSTSTORE_TYPE));
                sslConfiguration.setTrustRootCertDN(getNodeValue(trustStoreNode, SSL_TRUSTSTORE_CERTIFICATE_DN));
                sslConfiguration.setUseDefaultTrustManager(false);
                return sslConfiguration;
            }
     */
    protected static JSONObject toJSONOLD(SSLConfiguration sslConfiguration) {
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
        // If using the default java keystore, do NOT serialize the whole thing since it will be massive
        // and probably fail to store in any SQL backend.
        if (!sslConfiguration.isUseDefaultJavaTrustStore()) {
            byte[] keystore = null;

            try {
                InputStream is = sslConfiguration.getKeystoreIS();

                if (is != null) {

                    ByteArrayOutputStream baos = new ByteArrayOutputStream();

                    int nRead;
                    byte[] data = new byte[16384];

                    while ((nRead = is.read(data, 0, data.length)) != -1) {
                        baos.write(data, 0, nRead);
                    }

                    baos.flush();
                    keystore = baos.toByteArray();
                }
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
            if (keystore != null) {
                jsonUtil.setJSONValue(ssl, SSL_KEYSTORE_TAG, org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(keystore));
            }

        }

        return ssl;
    }


    public static SSLConfiguration fromJSON(JSONObject json) {
        try {
            return fromJSONNEW(json);
        } catch (Throwable t) {
            return fromJSONOLD(json);
        }
    }


    public static SSLConfiguration fromJSONNEW(JSONObject json) {
        SSLConfiguration ssl = new SSLConfiguration();
        JSONObject trustStore = json.getJSONObject(SSL_TRUSTSTORE_TAG);
        if (!trustStore.isEmpty()) {
            if(trustStore.containsKey(SSL_TRUSTSTORE_TYPE))ssl.setTrustRootType(trustStore.getString(SSL_TRUSTSTORE_TYPE));
            if(trustStore.containsKey(SSL_TRUSTSTORE_PASSWORD))ssl.setTrustRootPassword(trustStore.getString(SSL_TRUSTSTORE_PASSWORD));
            if(trustStore.containsKey(SSL_TRUSTSTORE_CERTIFICATE_DN))ssl.setTrustRootCertDN(trustStore.getString(SSL_TRUSTSTORE_CERTIFICATE_DN));
            if(trustStore.containsKey(SSL_TRUSTSTORE_PATH))ssl.setTrustRootPath(trustStore.getString(SSL_TRUSTSTORE_PATH));
            if(trustStore.containsKey(SSL_TRUSTSTORE_USE_JAVA_TRUSTSTORE))ssl.setUseDefaultJavaTrustStore(trustStore.getBoolean(SSL_TRUSTSTORE_USE_JAVA_TRUSTSTORE));
            if(trustStore.containsKey(SSL_TRUSTSTORE_USE_DEFAULT_TRUST_MANAGER))ssl.setUseDefaultTrustManager(trustStore.getBoolean(SSL_TRUSTSTORE_USE_DEFAULT_TRUST_MANAGER));
            if(trustStore.containsKey(SSL_TRUSTSTORE_IS_STRICT_HOSTNAMES))ssl.setStrictHostnames(trustStore.getBoolean(SSL_TRUSTSTORE_IS_STRICT_HOSTNAMES));
        }
        if (json.containsKey(SSL_KEYSTORE_TAG)) {
            JSONObject keystore = json.getJSONObject(SSL_KEYSTORE_TAG);
            if(keystore.containsKey(SSL_KEYSTORE_TYPE))ssl.setKeystoreType(keystore.getString(SSL_KEYSTORE_TYPE));
            if(keystore.containsKey(SSL_KEYSTORE_PASSWORD))ssl.setKeystorePassword(keystore.getString(SSL_KEYSTORE_PASSWORD));
            if(keystore.containsKey(SSL_KEYSTORE_PATH))ssl.setKeystore(keystore.getString(SSL_KEYSTORE_PATH));
        }
        return ssl;
    }

    public static SSLConfiguration fromJSONOLD(JSONObject json) {
        SSLConfiguration ssl = new SSLConfiguration();
        JSONUtil jsonUtil = getJSONUtil();
        ssl.setTlsVersion(jsonUtil.getJSONValueString(json, SSL_TLS_VERSION_TAG));
        ssl.setKeystoreType(jsonUtil.getJSONValueString(json, SSL_KEYSTORE_TYPE));
        ssl.setKeystorePassword(jsonUtil.getJSONValueString(json, SSL_KEYSTORE_PASSWORD));
        if (jsonUtil.hasKey(json, SSL_TRUSTSTORE_USE_JAVA_TRUSTSTORE)) {
            ssl.setUseDefaultJavaTrustStore(jsonUtil.getJSONValueBoolean(json, SSL_TRUSTSTORE_USE_JAVA_TRUSTSTORE));
        } else {
            ssl.setUseDefaultJavaTrustStore(true); // default should be to use the default trust store for java.
        }
        ssl.setKeystoreBytes(org.apache.commons.codec.binary.Base64.decodeBase64(jsonUtil.getJSONValueString(json, SSL_KEYSTORE_TAG)));
        // JSON does not have a concept of a path to a local file. The keystore value is the base 64 encoding of a file
        // to be used. The SSLConfig object, however, puts in a default value for the keystore path if the
        // use java option is enabled.
        if (!ssl.isUseDefaultJavaTrustStore()) {
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

    public static void main(String[] args) {
        SSLConfiguration ssl = new SSLConfiguration();
        ssl.setTlsVersion(TLS_VERSION_1_2);
        ssl.setStrictHostnames(true);
        ssl.setKeystore("/path/to/keystore");
        ssl.setKeystorePassword("woof");
        ssl.setKeystoreType("JKS");
        ssl.setTrustRootCertDN("CN=localhost");
        ssl.setTrustRootPassword("arf");
        ssl.setTrustRootPath("/path/to/trustroots");
        ssl.setTrustRootType("JKS");
        ssl.setUseDefaultTrustManager(false);
        ssl.setUseDefaultJavaTrustStore(true);
        System.out.println(toJSON(ssl).toString(2));

    }


}
