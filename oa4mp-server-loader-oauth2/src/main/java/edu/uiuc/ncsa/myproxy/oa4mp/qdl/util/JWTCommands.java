package edu.uiuc.ncsa.myproxy.oa4mp.qdl.util;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ExtendedParameters;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.OA2State;
import edu.uiuc.ncsa.qdl.evaluate.IOEvaluator;
import edu.uiuc.ncsa.qdl.exceptions.QDLException;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.extensions.QDLModuleMetaClass;
import edu.uiuc.ncsa.qdl.extensions.QDLVariable;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.QDLStem;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.oauth_2_0.JWTUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.*;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ExtendedParameters.OA4MP_NS;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/7/20 at  1:06 PM
 */
public class JWTCommands implements QDLModuleMetaClass {
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

    transient MyLoggingFacade logger = null;

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
    protected String CREATE_KEYS_NAME = "create_keys";

    public class CreateJWK implements QDLFunction {
        @Override
        public String getName() {
            return CREATE_KEYS_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1, 2};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            File target = null;
            Boolean useNewkeys = true;
            if (0 < objects.length) {
                target = new File(objects[0].toString());
            }
            if (1 < objects.length) {
                if (!(objects[1] instanceof Boolean)) {
                    throw new IllegalArgumentException("Error: " + getName() + " requires a boolean as its second argument.");
                }
                useNewkeys = (Boolean) objects[1];
            }
            try {
                JSONWebKeys newKeys = getSigningCommands().createJsonWebKeys();
                if (useNewkeys) {
                    jwks = newKeys;
                }
                if (!newKeys.hasDefaultKey()) {
                    for (String id : newKeys.keySet()) {
                        if ("RS256".equals(newKeys.get(id).algorithm)) {
                            newKeys.setDefaultKeyID(id);
                        }
                    }
                }
                JSONObject jsonObject = getJsonWebKeyUtil().toJSON(newKeys);
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
        public List<String> getDocumentation(int argCount) {
            List<String> doc = new ArrayList<>();
            switch (argCount) {
                case 0:
                    doc.add(getName() + "() - create a set of JSON WebKeys and sets the current set of web keys.");
                    break;
                case 1:
                    doc.add(getName() + "(file_name) - create a set of JSON WebKeys, sets this to the current set and writes them to the given file.");
                    break;
                case 2:
                    doc.add(getName() + "(file_name, true|false) - create a set of JSON WebKeys, writes them to the given file.");
                    doc.add("If the second argument is true, the current active set of keys is replaced.");
                    break;
                default:
                    return doc;
            }

            doc.add("If setting the current set of keys,  the default key will use RS256.");
            doc.add("See also: default_key");
            return doc;
        }
    }

    protected void writeWebkeys(JSONObject jsonObject, File target) throws IOException {
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add(jsonObject.toString(2));
        Files.write(target.toPath(), arrayList);
    }

    protected String LOAD_KEYS_NAME = "load_keys";

    public class LoadJWK implements QDLFunction {
        @Override
        public String getName() {
            return LOAD_KEYS_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
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
        public List<String> getDocumentation(int argCount) {
            List<String> docs = new ArrayList<>();
            docs.add(getName() + "(file_name) - loads the keys file in to the current session.");
            return docs;
        }
    }

    protected String SAVE_KEYS_NAME = "save_keys";

    public class SaveKeys implements QDLFunction {
        @Override
        public String getName() {
            return SAVE_KEYS_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
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
        public List<String> getDocumentation(int argCount) {
            List<String> docs = new ArrayList<>();
            docs.add(getName() + "(file_name) - saves the keys from current session to the given file.");
            return docs;
        }
    }

    SecureRandom random = new SecureRandom();

    public class SymmKeys implements QDLFunction {
        @Override
        public String getName() {
            return "create_skeys";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1, 2};
        }

        int defaultLength = 32;

        @Override
        public Object evaluate(Object[] objects, State state) {
            List<String> sKeys = null;
            int count = 1;
            int length = defaultLength;
            switch (objects.length) {
                case 0:
                    break;
                case 1:
                    if (!(objects[0] instanceof Long)) {
                        throw new IllegalArgumentException("Error: The first argument must be an integer");
                    }
                    Long lCount = (Long) objects[0];
                    count = lCount.intValue();
                    break;
                case 2:
                    if (!(objects[0] instanceof Long)) {
                        throw new IllegalArgumentException("Error: The first argument must be an integer");
                    }
                    lCount = (Long) objects[0];
                    count = lCount.intValue();
                    if (!(objects[1] instanceof Long)) {
                        throw new IllegalArgumentException("Error: The second argument must be an integer");
                    }
                    Long lLength = (Long) objects[1];
                    length = lLength.intValue();
                    break;
            }
            sKeys = createKeys(count, length);
            if (count == 1) {
                return sKeys.get(0);
            }
            List<Object> dummy = new ArrayList<>();
            dummy.addAll(sKeys); // how to cast a list of strings to a list of objects.
            QDLStem QDLStem = new QDLStem();
            QDLStem.addList(dummy);
            return QDLStem;
        }

        protected List<String> createKeys(int count, int length) {
            List<String> sKeys = new ArrayList<>();
            for (int i = 0; i < count; i++) {

                byte[] array = new byte[length];

                random.nextBytes(array);
                String output = Base64.getEncoder().encodeToString(array);

                while (output.endsWith("=")) {
                    output = output.substring(0, output.length() - 2);
                }
                sKeys.add(output);
            }
            return sKeys;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> docs = new ArrayList<>();
            switch (argCount) {
                case 0:
                    docs.add(getName() + "() - creates a single symmetric key.");
                    break;
                case 1:
                    docs.add(getName() + "(count) - create a stem list with this number. Default length is " + defaultLength + " bytes.");
                    break;
                case 2:
                    docs.add(getName() + "(count, length) - creates count keys of the " +
                            "given length (in bytes, not characters)");
            }
            docs.add("To save these to a file, use the " + IOEvaluator.WRITE_FILE + " command.");
            return docs;
        }
    }

    protected String DEFAULT_KEY_NAME = "default_key";

    public class DefaultKey implements QDLFunction {
        @Override
        public String getName() {
            return DEFAULT_KEY_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            if (jwks == null || jwks.isEmpty()) {
                return "";
            }
            if (objects.length == 0) {
                return jwks.getDefaultKeyID();
            }
            // so we have one.
            String newId = objects[0].toString();
            if (!jwks.containsKey(newId)) {
                throw new IllegalArgumentException("Error: There is no such key in the collection.");
            }
            String oldID = jwks.getDefaultKeyID();
            jwks.setDefaultKeyID(newId);
            return oldID;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> docs = new ArrayList<>();
            switch (argCount) {
                case 0:
                    docs.add(getName() + "() get the current default key used for signatures.");
                    break;
                case 1:
                    docs.add(getName() + "(new_id)  set the current default key used for signatures.");
            }
            return docs;
        }
    }

    protected String CREATE_JWT_NAME = "create_jwt";

    public class CreateJWT implements QDLFunction {
        @Override
        public String getName() {
            return CREATE_JWT_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1, 2};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            if(state instanceof OA2State){
                jwks =  ((OA2State)state).getJsonWebKeys();
            }
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
            QDLStem arg = (QDLStem) objects[0];


            try {
                return JWTUtil.createJWT((JSONObject) arg.toJSON(), jwks.get(kid));

            } catch (Throwable e) {
                throw new QDLException("Error creating JWT:" + e.getMessage(), e);
            }

        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> docs = new ArrayList<>();
            switch (argCount) {
                case 1:
                    docs.add(getName() + "(arg) takes a stem variable (the claims) and creates a signed JSON Web Token (JWT)");
                    docs.add("using the default id.");

                    break;
                case 2:
                    docs.add(getName() + "(arg,id) takes a stem variable (the claims) and creates a signed JSON Web Token (JWT)");
                    docs.add("using the given id from the current set of keys.");

            }
            docs.add("This returned  signed JWT is  a string.");
            docs.add("See also: " + CREATE_KEYS_NAME + ", " + DEFAULT_KEY_NAME + ", " + KEY_INFO_NAME);
            return docs;
        }
    }

    protected String KEY_INFO_NAME = "key_info";

    public class KeyInfo implements QDLFunction {
        @Override
        public String getName() {
            return KEY_INFO_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            if (jwks == null || jwks.isEmpty()) {
                throw new IllegalStateException("Error: No keys have been set.");
            }
            QDLStem QDLStem = new QDLStem();
            if (jwks.hasDefaultKey()) {
                QDLStem.put("default", jwks.getDefaultKeyID());
            }
            for (String id : jwks.keySet()) {
                JSONWebKey jwk = jwks.get(id);
                QDLStem entry = new QDLStem();
                entry.put(JSONWebKeyUtil.ALGORITHM, jwk.algorithm);
                entry.put(JSONWebKeyUtil.KEY_TYPE, jwk.use);
                entry.put(JSONWebKeyUtil.KEY_TYPE, jwk.type);
                QDLStem.put(id, entry);
            }
            return QDLStem;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> docs = new ArrayList<>();
            docs.add(getName() + "() - return a stem variable consisting of the ids (as keys) and the algorithms (as the values).");
            docs.add("See also:" + DEFAULT_KEY_NAME);
            return docs;
        }
    }

    protected String VERIFY_JWT_NAME = "verify_jwt";

    public class VerifyJWT implements QDLFunction {
        @Override
        public String getName() {
            return VERIFY_JWT_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1, 2};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
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
            QDLStem QDLStem = new QDLStem();
            QDLStem.fromJSON(json);
            return QDLStem;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> docs = new ArrayList<>();
            switch (argCount) {
                case 1:
                    docs.add(getName() + "(jwt) - This will decode the jwt and verify the signature, using the current set of keys.");
                    break;
                case 2:
                    docs.add(getName() + "(jwt, url) - This will decode the jwt and verify the signature using the");
                    docs.add("well-known url for a service and the (public) key there.");
            }
            docs.add("If the signature is not valid, an error is raised.");
            docs.add("See also:" + DEFAULT_KEY_NAME + ", " + CREATE_KEYS_NAME);
            return docs;
        }
    }

    protected String GET_HEADER_NAME = "get_header";

    public class GetHeader implements QDLFunction {
        @Override
        public String getName() {
            return GET_HEADER_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            String token = objects[0].toString();

            JSONObject[] array = JWTUtil.readJWT(token);
            QDLStem QDLStem = new QDLStem();
            QDLStem.fromJSON(array[JWTUtil.HEADER_INDEX]);
            return QDLStem;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> docs = new ArrayList<>();
            docs.add(getName() + "(arg) takes a JWT and returns the header as a stem. This does no verification.");
            docs.add("See also:" + GET_PAYLOAD_NAME);
            return docs;

        }
    }

    protected String GET_PAYLOAD_NAME = "get_payload";

    public class GetPayload implements QDLFunction {
        @Override
        public String getName() {
            return GET_PAYLOAD_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            String token = objects[0].toString();

            JSONObject[] array = JWTUtil.readJWT(token);
            QDLStem QDLStem = new QDLStem();
            QDLStem.fromJSON(array[JWTUtil.PAYLOAD_INDEX]);
            return QDLStem;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> docs = new ArrayList<>();
            docs.add(getName() + "(arg) takes a JWT and returns the payload as a stem. This does no verification.");
            docs.add("See also:" + GET_HEADER_NAME);
            return docs;

        }
    }

    /**
     * A list of scopes for testing.
     */
    public class TestScopes implements QDLVariable {
        @Override
        public String getName() {
            return "test_scopes.";
        }

        QDLStem QDLStem = null;

        @Override
        public Object getValue() {
            if (QDLStem == null) {
                QDLStem = new QDLStem();
                List<Object> scopes = new ArrayList<>();
                scopes.add("wlcg");
                scopes.add("compute.exec:/");
                scopes.add("compute.create:/");
                scopes.add("storage.write:/store/data");
                scopes.add("storage.read:/store ");
                QDLStem.addList(scopes);
            }
            return QDLStem;
        }
    }

    public class TestXAs implements QDLVariable {
        @Override
        public String getName() {
            return "test_xas.";
        }

        QDLStem QDLStem = null;

        @Override
        public Object getValue() {
            if (QDLStem == null) {
                QDLStem = new QDLStem();
                HashMap<String, String[]> pmap = new HashMap<>();
                pmap.put(OA4MP_NS + ":/roles/", new String[]{"A", "B", "C"});
                pmap.put(OA4MP_NS + ":/tokens/id/lifetime", new String[]{"100000000"});
                pmap.put(OA4MP_NS + ":/tokens/access/lifetime", new String[]{"500000"});
                ExtendedParameters xp = new ExtendedParameters();
                JSONObject jsonObject = xp.snoopParameters(pmap);
                QDLStem.fromJSON(jsonObject);
            }
            return QDLStem;
        }
    }


    public class TestAudience implements QDLVariable {
        @Override
        public String getName() {
            return "test_audience.";
        }

        QDLStem QDLStem = null;

        @Override
        public Object getValue() {
            if (QDLStem == null) {
                QDLStem = new QDLStem();
                List<Object> audience = new ArrayList<>();
                audience.add("https://foo.edu/bar");
                audience.add("https://foo.edu/baz");
                QDLStem.addList(audience);
            }
            return QDLStem;
        }

    }

    public class TestClaims implements QDLVariable {
        @Override
        public String getName() {
            return "test_claims.";
        }

        QDLStem QDLStem = null;

        @Override
        public Object getValue() {
            if (QDLStem == null) {
                QDLStem = new QDLStem();
                QDLStem.fromJSON(JSONObject.fromObject(rawJSON));
            }
            return QDLStem;
        }

        String rawJSON = "{\n" +
                "  \"iss\": \"https://test.cilogon.org\",\n" +
                "  \"sub\": \"http://cilogon.org/serverT/users/17048\",\n" +
                "  \"aud\": \"myproxy:oa4mp,2012:/client_id/910d7984412870aa6e199f9afrab8\",\n" +
                "  \"auth_time\": \"" + (System.currentTimeMillis() / 1000) + "\",\n" +
                "  \"exp\": " + (3600 * 24 * 11 + System.currentTimeMillis() / 1000) + ",\n" +
                "  \"iat\": " + (System.currentTimeMillis() / 1000) + ",\n" +
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
    protected String CREATE_UUID = "create_uuid";
   public class Create_UUID implements QDLFunction{
       @Override
       public String getName() {
           return CREATE_UUID;
       }

       @Override
       public int[] getArgCount() {
           return new int[]{0};
       }

       @Override
       public Object evaluate(Object[] objects, State state) {
           UUID uuid = UUID.randomUUID();

           return uuid.toString();
       }

       @Override
       public List<String> getDocumentation(int argCount) {
           List<String>doxx = new ArrayList<>();
           doxx.add(getName() + " create a new uuid.");
           doxx.add("This returns a string.");
           return doxx;
       }
   }
}
