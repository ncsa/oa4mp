package edu.uiuc.ncsa.oa2.qdl;

import edu.uiuc.ncsa.myproxy.oauth2.tools.SigningCommands;
import edu.uiuc.ncsa.qdl.exceptions.QDLException;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.extensions.QDLVariable;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.oauth_2_0.JWTUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.net.URI;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/7/20 at  1:06 PM
 */
public class JWTCommands implements Serializable {
    JSONWebKeys jwks;

    public JWTCommands(MyLoggingFacade logger) {
        this.logger = logger;
    }

    public MyLoggingFacade getLogger() {
        return logger;
    }

    public void setLogger(MyLoggingFacade logger) {
        this.logger = logger;
    }

    MyLoggingFacade logger = null;

    public SigningCommands getSigningCommands() {
        if (signingCommands == null) {
            signingCommands = new SigningCommands(null);

        }
        return signingCommands;
    }

    public JSONWebKeyUtil getJsonWebKeyUtil() {
        if (jsonWebKeyUtil == null) {
            jsonWebKeyUtil = new JSONWebKeyUtil();
        }
        return jsonWebKeyUtil;
    }

    transient SigningCommands signingCommands = null;
    transient JSONWebKeyUtil jsonWebKeyUtil = null;

    public class CreateJWK implements QDLFunction {
        @Override
        public String getName() {
            return "create_keys";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects) {
            File target = null;
            if (objects.length == 1) {
                target = new File(objects[0].toString());
            }
            try {
                jwks = getSigningCommands().createJsonWebKeys();
                if (jwks.hasDefaultKey()) {
                    for (String id : jwks.keySet()) {
                        if ("RS256".equals(jwks.get(id).algorithm)) {
                            jwks.setDefaultKeyID(id);
                        }
                    }
                }
                JSONObject jsonObject = getJsonWebKeyUtil().toJSON(jwks);
                if (target == null) {
                    return true;
                }
                writeWebkeys(jsonObject, target);
            } catch (Throwable e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                }
                throw new QDLException("Error: Could not create JSON web keys" + e.getMessage(), e);
            }
            return true;
        }

        @Override
        public List<String> getDocumentation() {
            List<String> doc = new ArrayList<>();
            doc.add(getName() + "([file_name]) - create a set of JSON WebKeys and sets the current set of web keys.");
            doc.add("If you specify a file, then the result will be written there, otherwise this will return the keys as a stem.");
            return doc;
        }
    }

    protected void writeWebkeys(JSONObject jsonObject, File target) throws IOException {
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add(jsonObject.toString(2));
        Files.write(target.toPath(), arrayList);
    }

    public class LoadJWK implements QDLFunction {
        @Override
        public String getName() {
            return "load_keys";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects) {
            if (objects.length != 1) {
                throw new IllegalArgumentException("Error:" + getName() + " requires a file name");
            }
            File f = new File(objects[0].toString());
            if (!f.exists()) {
                throw new IllegalArgumentException("Error: The file \"" + f.getAbsolutePath() + "\" does not exist.");
            }
            if (f.isDirectory()) {
                throw new IllegalArgumentException("Error:  \"" + f.getAbsolutePath() + "\" is a directory.");
            }
            if (!f.canRead()) {
                throw new QDLException("Error: Access denied to \"" + f.getAbsolutePath() + "\".");
            }
            try {
                String rawJSON = new String(Files.readAllBytes(f.toPath()));
                jwks = getJsonWebKeyUtil().fromJSON(rawJSON);
            } catch (Throwable e) {
                throw new QDLException("Error reading keys file:" + e.getMessage(), e);
            }

            return true;
        }

        @Override
        public List<String> getDocumentation() {
            List<String> docs = new ArrayList<>();
            docs.add(getName() + "(file_name) - loads the keys file in to the current session.");
            return docs;
        }
    }

    public class SaveKeys implements QDLFunction {
        @Override
        public String getName() {
            return "save_keys";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects) {
            if (objects.length != 1) {
                throw new IllegalArgumentException("Error: " + getName() + " requires a file name.");
            }
            if (jwks == null || jwks.isEmpty()) {
                throw new IllegalStateException("Error: No keys found to save.");
            }

            File target = new File(objects[0].toString());
            try {
                writeWebkeys(getJsonWebKeyUtil().toJSON(jwks), target);
            } catch (IOException e) {
                throw new QDLException("Error: could not save keys to " + target.getAbsolutePath(), e);
            }

            return true;

        }

        @Override
        public List<String> getDocumentation() {
            List<String> docs = new ArrayList<>();
            docs.add(getName() + "(file_name) - saves the keys from current session to the given file.");
            return docs;
        }
    }

    public class CreateJWT implements QDLFunction {
        @Override
        public String getName() {
            return "create_jwt";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1, 2};
        }

        @Override
        public Object evaluate(Object[] objects) {
            if (jwks == null || jwks.isEmpty()) {
                throw new IllegalStateException("Error: no keys loaded.");
            }
            String kid = null;
            if (objects.length == 2) {
                kid = objects[1].toString();
            } else {
                if (!jwks.hasDefaultKey()) {
                    throw new IllegalStateException("Error: no default key.");
                }
                kid = jwks.getDefaultKeyID();

            }
            StemVariable arg = (StemVariable) objects[0];


            try {
                return JWTUtil.createJWT((JSONObject) arg.toJSON(), jwks.get(kid));

            } catch (Throwable e) {
                throw new QDLException("Error creating JWT:" + e.getMessage(), e);
            }

        }

        @Override
        public List<String> getDocumentation() {
            List<String> docs = new ArrayList<>();
            docs.add(getName() + "(arg[,id]) takes a stem variable (the claims) and returns a signed JSON WEb Token (JWT).");
            docs.add("If an id is supplied, that will be used, otherwise the default id for the set of web keys will be used.");
            docs.add("This returned  signed JWT is  a string.");
            return docs;
        }
    }

    public class KeyInfo implements QDLFunction {
        @Override
        public String getName() {
            return "key_info";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects) {
            if (jwks == null || jwks.isEmpty()) {
                throw new IllegalStateException("Error: No keys have been set.");
            }
            StemVariable stemVariable = new StemVariable();
            if (jwks.hasDefaultKey()) {
                stemVariable.put("default", jwks.getDefaultKeyID());
            }
            for (String id : jwks.keySet()) {
                JSONWebKey jwk = jwks.get(id);
                StemVariable entry = new StemVariable();
                entry.put(JSONWebKeyUtil.ALGORITHM, jwk.algorithm);
                entry.put(JSONWebKeyUtil.KEY_TYPE, jwk.use);
                entry.put(JSONWebKeyUtil.KEY_TYPE, jwk.type);
                stemVariable.put(id, entry);
            }
            return stemVariable;
        }

        @Override
        public List<String> getDocumentation() {
            List<String> docs = new ArrayList<>();
            docs.add(getName() + "() - return a stem variable consisting of the ids (as keys) and the algorithms (as the values).");
            return docs;
        }
    }

    public class VerifyJWT implements QDLFunction {
        @Override
        public String getName() {
            return "verify_jwt";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1, 2};
        }

        @Override
        public Object evaluate(Object[] objects) {
            if (jwks == null || jwks.isEmpty()) {
                throw new IllegalStateException("Error: No keys have been set.");
            }
            URI well_known = null;
            if (objects.length == 2) {
                try {
                    well_known = URI.create(objects[1].toString());
                } catch (Throwable t) {
                    throw new IllegalArgumentException("Error: The second argument \"" + objects[1] + "\" must be a valid URI.");
                }
            }
            String token = objects[0].toString();
            JSONObject json;
            if (well_known == null) {

                json = JWTUtil.verifyAndReadJWT(token, jwks);
            } else {

                json = JWTUtil.verifyAndReadJWT(token, well_known);
            }
            StemVariable stemVariable = new StemVariable();
            stemVariable.fromJSON(json);
            return stemVariable;
        }

        @Override
        public List<String> getDocumentation() {
            List<String> docs = new ArrayList<>();
            docs.add(getName() + "(jwt[,url]) - This will decode the jwt and verify the signature.");
            docs.add("The header (part of the JWT) has a keyt id, if this is not in the current jwks, then");
            docs.add("e.g., it is at the well-known url for a service, yo may supply that, the key will be retrieved");
            docs.add("before being verified. If the signature is not valid, an error is raised.");
            return docs;
        }
    }

    public class GetHeader implements QDLFunction {
        @Override
        public String getName() {
            return "get_header";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects) {
            String token = objects[0].toString();

            JSONObject[] array = JWTUtil.readJWT(token);
            StemVariable stemVariable = new StemVariable();
            stemVariable.fromJSON(array[JWTUtil.HEADER_INDEX]);
            return stemVariable;
        }

        @Override
        public List<String> getDocumentation() {
            List<String> docs = new ArrayList<>();
            docs.add(getName() + "(arg) takes a JWT and returns the header as a stem. This does no verification.");
            return docs;

        }
    }

    public class GetPayload implements QDLFunction {
        @Override
        public String getName() {
            return "get_payload";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects) {
            String token = objects[0].toString();

            JSONObject[] array = JWTUtil.readJWT(token);
            StemVariable stemVariable = new StemVariable();
            stemVariable.fromJSON(array[JWTUtil.PAYLOAD_INDEX]);
            return stemVariable;
        }

        @Override
        public List<String> getDocumentation() {
            List<String> docs = new ArrayList<>();
            docs.add(getName() + "(arg) takes a JWT and returns the payload as a stem. This does no verification.");
            return docs;

        }
    }

    public class TestClaims implements QDLVariable {
        @Override
        public String getName() {
            return "test_claims.";
        }

        StemVariable stemVariable = null;

        @Override
        public Object getValue() {
            if (stemVariable == null) {
                stemVariable = new StemVariable();
                stemVariable.fromJSON(JSONObject.fromObject(rawJSON));
            }
            return stemVariable;
        }

        String rawJSON = "{\n" +
                "  \"iss\": \"https://test.cilogon.org\",\n" +
                "  \"sub\": \"http://cilogon.org/serverT/users/17048\",\n" +
                "  \"aud\": \"myproxy:oa4mp,2012:/client_id/10d798441270aa6e199f9afaab8\",\n" +
                "  \"auth_time\": \"1586292128\",\n" +
                "  \"exp\": 1586293028,\n" +
                "  \"iat\": 1586292128,\n" +
                "  \"nonce\": \"R72KPZ4Pwo9nPd9z1qCA04hBALMC-yVGUOGyTn-miHo\",\n" +
                "  \"email\": \"bob@bigstate.edu\",\n" +
                "  \"given_name\": \"Robert\",\n" +
                "  \"family_name\": \"Bruce\",\n" +
                "  \"name\": \"Roibert a Briuis\",\n" +
                "  \"cert_subject_dn\": \"/DC=org/DC=cilogon/C=US/O=Big State Supercomputing Center/CN=Robert Bruce T17099\",\n" +
                "  \"idp\": \"https://idp.bigstate.edu/idp/shibboleth\",\n" +
                "  \"idp_name\": \"Supercomputing at BSU\",\n" +
                "  \"eppn\": \"rbriuis@bigstate.edu\",\n" +
                "  \"eptid\": \"https://idp.bigstate.edu/idp/shibboleth!https://cilogon.org/shibboleth!65P3o9FNjrp4z6+WI7Dir/4I=\",\n" +
                "  \"affiliation\": \"staff@bigstate.edu;employee@bigstate.edu;member@bigstate.edu\",\n" +
                "  \"acr\": \"https://refeds.org/profile/mfa\",\n" +
                "  \"uid\": \"rbriuis\",\n" +
                "  \"voPersonExternalID\": \"rbriuis@bigstate.edu\",\n" +
                "  \"uidNumber\": \"55939\",\n" +
                "  \"isMemberOf\":   [" +
                "  {\n" +
                "      \"name\": \"all_users\",\n" +
                "      \"id\": 13002\n" +
                "    },\n" +
                "        {\n" +
                "      \"name\": \"staff_reporting\",\n" +
                "      \"id\": 16405\n" +
                "    },\n" +
                "        {\n" +
                "      \"name\": \"list_allbsu\",\n" +
                "      \"id\": 18942\n" +
                "    }\n" +
                "  ]\n" +
                "}";
    }
}
