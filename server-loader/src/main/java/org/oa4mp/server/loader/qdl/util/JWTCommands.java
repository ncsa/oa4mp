package org.oa4mp.server.loader.qdl.util;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.jwk.JWKUtil2;
import net.sf.json.JSONObject;
import org.oa4mp.delegation.server.JWTUtil;
import org.oa4mp.delegation.server.jwt.MyOtherJWTUtil2;
import org.oa4mp.server.loader.oauth2.state.ExtendedParameters;
import org.oa4mp.server.loader.qdl.scripting.OA2State;
import org.qdl_lang.evaluate.IOEvaluator;
import org.qdl_lang.exceptions.BadArgException;
import org.qdl_lang.exceptions.QDLException;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.extensions.QDLVariable;
import org.qdl_lang.state.State;
import org.qdl_lang.util.QDLFileUtil;
import org.qdl_lang.variables.Constant;
import org.qdl_lang.variables.QDLStem;
import org.qdl_lang.variables.values.BooleanValue;
import org.qdl_lang.variables.values.QDLNullValue;
import org.qdl_lang.variables.values.QDLValue;
import org.qdl_lang.variables.values.StringValue;

import java.net.URI;
import java.security.SecureRandom;
import java.util.*;

import static org.oa4mp.server.loader.oauth2.state.ExtendedParameters.OA4MP_NS;
import static org.qdl_lang.variables.StemUtility.put;
import static org.qdl_lang.variables.values.QDLValue.asQDLValue;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/7/20 at  1:06 PM
 */
public class JWTCommands  {
    JWKUtil2 jwkUtil;
    public boolean hasJWKS(){
        return !((jwks == null) || jwks.isEmpty());
    }
    public JSONWebKeys getJwks() {
        return jwks;
    }

    public void setJwks(JSONWebKeys jwks) {
        if(jwks == null) {
            jwkStem = null;
        }else{
            jwkStem = new QDLStem();
            jwkStem.fromJSON(getJsonWebKeyUtil().toJSON(jwks));
        }
        this.jwks = jwks;
    }

    JSONWebKeys jwks;

    public QDLStem getJwkStem() {
        return jwkStem;
    }

    QDLStem jwkStem;

    public JWKUtil2 getJwkUtil() {
        if (jwkUtil == null) {
            jwkUtil = new JWKUtil2();
        }
        return jwkUtil;
    }

    public void setJwkUtil(JWKUtil2 jwkUtil) {
        this.jwkUtil = jwkUtil;
    }


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

    public SigningCommands getSigningCommands() throws Throwable {
        if (signingCommands == null) {
            signingCommands = new SigningCommands(null);

        }
        return signingCommands;
    }

    public JWKUtil2 getJsonWebKeyUtil() {
        if (jsonWebKeyUtil == null) {
            jsonWebKeyUtil = new JWKUtil2();
        }
        return jsonWebKeyUtil;
    }

    transient SigningCommands signingCommands = null;
    transient JWKUtil2 jsonWebKeyUtil = null;
    protected String CREATE_KEYS_NAME = "create_keys";

    public static String ARG_KEY_TYPE = "type";
    public static String ARG_DEFAULT_KEY_ID = "default_key_id";
    public static String ARG_RSA_KEY_SIZE_TYPE = "size";
    public static String ARG_EC_CURVE_TYPE = "curve";
    public static String ARG_FILE_PATH_TYPE = "file";
    public static String ARG_FILE_OVERWRITE_TYPE = "force";
    public static String ARG_SET_TO_CURRENT_KEYS_TYPE = "set";


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
        public QDLValue evaluate(QDLValue[] objects, State state) {
            // {'type':'RSA'|'EC', 'file':'path','force':true|false, 'set':true|false}
            String keyType = "RSA";
            String ecCurve = null;
            int rsaKeySize = 2048;
            String filePath = null;
            String defaultKeyID = null;
            boolean overwriteFile = false;
            boolean setCurrent = false;
            boolean argTypeOk = false; // The argument passed to the function was not a stem |string(if monadic)
            switch (objects.length) {
                case 0:
                    // do nothing, accept defaults
                    argTypeOk = true;
                    break;
                case 1:

                    if (objects[0].isString()) {
                        argTypeOk = true;
                        filePath = objects[0].asString();
                    }
                    if (objects[0].isStem()) {
                        QDLStem args = objects[0].asStem();
                        argTypeOk = true;
                        if (args.containsKey(ARG_KEY_TYPE)) {
                            if (!Constant.isString(args.get(ARG_KEY_TYPE))) {
                                throw new BadArgException(getName() + " requires a string as the " + ARG_KEY_TYPE + " of the key.",0);
                            }
                            keyType = args.getString(ARG_KEY_TYPE);
                        }
                        if (args.containsKey(ARG_DEFAULT_KEY_ID)) {
                            if (!args.get(ARG_DEFAULT_KEY_ID).isString()) {
                                throw new BadArgException(getName() + " requires a string as the " + ARG_DEFAULT_KEY_ID + " of the generated keys.",0);
                            }
                            defaultKeyID = args.getString(ARG_DEFAULT_KEY_ID);

                        }
                        if (args.containsKey(ARG_FILE_PATH_TYPE)) {
                            if (!args.get(ARG_FILE_PATH_TYPE).isString()) {
                                throw new BadArgException(getName() + " requires a string as the " + ARG_FILE_PATH_TYPE + " of the generated keys.",0);
                            }
                            filePath = args.getString(ARG_FILE_PATH_TYPE);
                        }
                        if (args.containsKey(ARG_FILE_OVERWRITE_TYPE)) {
                            if (!args.get(ARG_KEY_TYPE).isBoolean()) {
                                throw new BadArgException(getName() + " requires a boolean as the " + ARG_FILE_OVERWRITE_TYPE + " argument.",0);
                            }
                            overwriteFile = args.getBoolean(ARG_FILE_OVERWRITE_TYPE);
                        }
                        if (args.containsKey(ARG_SET_TO_CURRENT_KEYS_TYPE)) {
                            if (!args.get(ARG_SET_TO_CURRENT_KEYS_TYPE).isBoolean()) {
                                throw new BadArgException(getName() + " requires a boolean as the " + ARG_SET_TO_CURRENT_KEYS_TYPE + " argument.",0);
                            }
                            setCurrent = args.getBoolean(ARG_SET_TO_CURRENT_KEYS_TYPE);
                        }
                        if (args.containsKey(ARG_RSA_KEY_SIZE_TYPE)) {
                            if (!args.get(ARG_RSA_KEY_SIZE_TYPE).isLong()) {
                                throw new BadArgException(getName() + " requires an integer as the " + ARG_RSA_KEY_SIZE_TYPE + " argument.",0);
                            }
                            rsaKeySize = args.getLong(ARG_RSA_KEY_SIZE_TYPE).intValue();
                        }
                        if (args.containsKey(ARG_EC_CURVE_TYPE)) {
                            if (!args.get(ARG_EC_CURVE_TYPE).isStem()) {
                                throw new BadArgException(getName() + " requires a string as the " + ARG_EC_CURVE_TYPE + " of the generated keys.",0);
                            }
                            ecCurve = args.getString(ARG_EC_CURVE_TYPE);
                        }
                    }
                    break;
                case 2:
                    if (objects[0].isString()) {
                        filePath = objects[0].asString();
                    } else {
                        throw new BadArgException("In dyadic " + getName() + ", the first argument must be a string",0);
                    }
                    if (objects[1].isBoolean()) {
                        overwriteFile = objects[1].asBoolean();
                    } else {
                        throw new BadArgException("In dyadic " + getName() + ", the second argument must be a boolean",1);

                    }
                    break;
            }
            if (!argTypeOk) {
                throw new BadArgException("Unsupport arg type as first argument to " + getName(),0);
            }
            try {
                JSONWebKeys newKeys = null;
                if (keyType.equals("RSA")) {

                    newKeys = getSigningCommands().createRSAJsonWebKeys(rsaKeySize, defaultKeyID);
                }
                if (keyType.equals("EC")) {
                    newKeys = getSigningCommands().createECJsonWebKeys(ecCurve);
                }
                if (newKeys == null) {
                    throw new IllegalArgumentException("unsupported key type '" + keyType + "'");
                }

                if (setCurrent || !hasJWKS()) {
                    setJwks(newKeys);
                }
                if (!newKeys.hasDefaultKey()) {
                    for (String id : newKeys.keySet()) {
                        if (JWKUtil2.ES_256.equals(newKeys.get(id).algorithm) || JWKUtil2.RS_256.equals(newKeys.get(id).algorithm)) {
                            newKeys.setDefaultKeyID(id);
                        }
                    }
                }
                JSONObject jsonObject = getJsonWebKeyUtil().toJSON(newKeys);
                if (filePath != null) {
                    // only try to do file stuff if they have set it up.
                    if (overwriteFile) {
                        writeWebkeys(state, jsonObject, filePath);
                    } else {
                        if (!QDLFileUtil.exists(state, filePath)) {
                            writeWebkeys(state, jsonObject, filePath);
                        }
                    }
                }
                QDLStem outKeys = new QDLStem();
                outKeys.fromJSON(jsonObject);
                return asQDLValue(outKeys);

            } catch (Throwable e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                }
                throw new QDLException(" Could not create JSON web keys" + e.getMessage(), e);
            }
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doc = new ArrayList<>();
            switch (argCount) {
                case 0:
                    doc.add(getName() + "() - create a set of RSA JSON WebKeys and sets the current set of web keys.");
                    break;
                case 1:
                    doc.add(getName() + "(arg. | file_path) - create a set of JSON WebKeys.");
                    doc.add("file_path - create a set of RSA JSON web keys, set current keys to them and write to the file");
                    doc.add("     arg. - stem of options. {'" + ARG_KEY_TYPE + "':'RSA'|'EC', " +
                            "'" + ARG_RSA_KEY_SIZE_TYPE + "':rsa_key_size," +
                            "'" + ARG_FILE_PATH_TYPE + "':'path'," +
                            "'" + ARG_FILE_OVERWRITE_TYPE + "':true|false, " +
                            "'" + ARG_SET_TO_CURRENT_KEYS_TYPE + "':true|false}");
                    doc.add("            " + ARG_KEY_TYPE + " = of type RSA or EC (default is RSA)");
                    doc.add("            " + ARG_EC_CURVE_TYPE + " = name of the elliptic curve to use, default is " + JWKUtil2.EC_CURVE_P_256);
                    doc.add("            " + ARG_RSA_KEY_SIZE_TYPE + " = size of the RSA keys, default is 2048");
                    doc.add("            " + ARG_FILE_PATH_TYPE + " = path to file (if missing no write is done)");
                    doc.add("            " + ARG_FILE_OVERWRITE_TYPE + " = overwrite file if present (default is false, ignore if no file)");
                    doc.add("            " + ARG_SET_TO_CURRENT_KEYS_TYPE + " = set to the current keys for this module.");
                    doc.add("If there are no keys active, it will set the new keys to the current ones.");
                    doc.add("Otherwise, you must tell it to do so.");
                    break;
                case 2:
                    doc.add(getName() + "(file_path, true|false) - create a set of RSA JSON WebKeys, writes them to the given file.");
                    doc.add("If the second argument is true, the current active set of keys is replaced.");
                    doc.add("This is equivalent to {'"
                            + ARG_KEY_TYPE + "':'RSA', '"
                            + ARG_FILE_PATH_TYPE + "':'file_path', '"
                            + ARG_FILE_OVERWRITE_TYPE + "':false, '"
                            + ARG_SET_TO_CURRENT_KEYS_TYPE + "':true|false}");
                    break;
                default:
                    return doc;
            }

            doc.add("\nThis also returns the newly generated set of keys as the output.");
            doc.add("If you are replacing the current keys with the new one, the default is set to");
            doc.add("key with algorithm " + JWKUtil2.RS_256 + " (if RSA) or " + JWKUtil2.ES_256 + " (if elliptic)");
            doc.add("RSA keys follow https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3");
            doc.add("EC keys follow https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4");
            doc.add("See also: default_key");
            return doc;
        }
    }

    protected void writeWebkeys(State state, JSONObject jsonObject, String target) throws Throwable {
        QDLFileUtil.writeTextFile(state, target, jsonObject.toString(2));
        //Files.write(target.toPath(), arrayList);
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
        public QDLValue evaluate(QDLValue[] objects, State state) {
            if (!(objects[0].isString())) {
                throw new BadArgException(getName() + " requires a string as its argument",0);
            }
            String filePath = objects[0].asString();
            try {
                //String rawJSON = new String(Files.readAllBytes(f.toPath()));
                String rawJSON = QDLFileUtil.readTextFile(state, filePath);
                setJwks(getJsonWebKeyUtil().fromJSON(rawJSON));
            } catch (Throwable e) {
                throw new QDLException("Error reading keys file:" + e.getMessage(), e);
            }

            return BooleanValue.True;
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
        public QDLValue evaluate(QDLValue[] objects, State state) {
             if (!hasJWKS()) {
                throw new IllegalStateException(" No keys found to save.");
            }
            if (!objects[0].isString()) {
                throw new BadArgException(getName() + " requires a string as its argument",0);
            }
            try {
                writeWebkeys(state, getJsonWebKeyUtil().toJSON(jwks), objects[0].asString());
            } catch (Throwable e) {
                throw new QDLException(" could not save keys to " + objects[0], e);
            }
            return BooleanValue.True;
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
        public QDLValue evaluate(QDLValue[] objects, State state) {
            List<String> sKeys = null;
            int count = 1;
            int length = defaultLength;
            switch (objects.length) {
                case 0:
                    break;
                case 1:
                    if (!(objects[0].isLong())) {
                        throw new BadArgException(" The first argument must be an integer",0);
                    }
                    Long lCount = objects[0].asLong();
                    count = lCount.intValue();
                    break;
                case 2:
                    if (!(objects[0].isLong())) {
                        throw new BadArgException(" The first argument must be an integer",0);
                    }
                    lCount = objects[0].asLong();
                    count = lCount.intValue();
                    if (!(objects[1].isLong())) {
                        throw new BadArgException(" The second argument must be an integer",1);
                    }
                    Long lLength = objects[1].asLong();
                    length = lLength.intValue();
                    break;
            }
            sKeys = createKeys(count, length);
            if (count == 1) {
                return asQDLValue(sKeys.get(0));
            }
            List<Object> dummy = new ArrayList<>();
            dummy.addAll(sKeys); // how to cast a list of strings to a list of objects.
            QDLStem QDLStem = new QDLStem();
            QDLStem.addList(dummy);
            return asQDLValue(QDLStem);
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
        public QDLValue evaluate(QDLValue[] objects, State state) {
            if (!hasJWKS()) {
                return new StringValue();
            }
            if (objects.length == 0) {
                return asQDLValue(getJwks().getDefaultKeyID());
            }
            // so we have one.
            String newId = objects[0].asString();
            if (!getJwks().containsKey(newId)) {
                throw new BadArgException(" There is no such key in the collection.",0);
            }
            String oldID = getJwks().getDefaultKeyID();
            getJwks().setDefaultKeyID(newId);
            return asQDLValue(oldID);
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

    protected String CURRENT_KEYS = "jwks"; // would use "keys" but that clashes with QDL built-in

    public class Keys implements QDLFunction {
        @Override
        public String getName() {
            return CURRENT_KEYS;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public QDLValue evaluate(QDLValue[] objects, State state) throws Throwable {
            if (objects.length == 0) {
                // query current keys
                if (jwks == null) {
                    return QDLNullValue.getNullValue();
                }
                QDLStem out = new QDLStem();
                // improvement is to have a parallel version of this and just return it.
                return asQDLValue(out.fromJSON(getJsonWebKeyUtil().toJSON(jwks)));
            }
            if (!(objects[0].isStem())) {
                throw new BadArgException("no key specified",0);
            }
            QDLStem stem = objects[0].asStem();
            QDLStem old = getJwkStem();
            setJwks(getJsonWebKeyUtil().fromJSON(stem.toJSON()));
            if (old == null) {
                return QDLNullValue.getNullValue();
            }
            return asQDLValue(old);
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doc = new ArrayList<>();
            switch (argCount){
                case 0:
                    doc.add(getName() + "() - return current jwk set or none if there are none");
                    break;
                case 1:
                    doc.add(getName() + "(keys.) - set the current keys to this stem");
                    doc.add("this returns the previously active keys or null if there was none.");
                    break;
            }
            return doc;
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
        public QDLValue evaluate(QDLValue[] objects, State state) {
            if (state instanceof OA2State) {
                setJwks(((OA2State) state).getJsonWebKeys());
            }
            if (!hasJWKS()) {
                throw new IllegalStateException(" no keys loaded.");
            }
            String kid = null;
            if (objects.length == 2) {
                kid = objects[1].toString();
            } else {
                if (!getJwks().hasDefaultKey()) {
                    throw new IllegalStateException(" no default key.");
                }
                kid = getJwks().getDefaultKeyID();

            }
            QDLStem arg = objects[0].asStem();


            try {
                return asQDLValue(JWTUtil.createJWT((JSONObject) arg.toJSON(), getJwks().get(kid)));

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
        public QDLValue evaluate(QDLValue[] objects, State state) {
            if (!hasJWKS()) {
                throw new IllegalStateException(" No keys have been set.");
            }
            QDLStem QDLStem = new QDLStem();
            if (getJwks().hasDefaultKey()) {
                put(QDLStem, "default", getJwks().getDefaultKeyID());
            }
            for (String id : getJwks().keySet()) {
                JSONWebKey jwk = getJwks().get(id);
                QDLStem entry = new QDLStem();
                put(entry, MyOtherJWTUtil2.ALGORITHM, jwk.algorithm);
                put(entry, JWKUtil2.USE, jwk.use);
                put(entry, JWKUtil2.KEY_TYPE, jwk.type);
                put(QDLStem, id, entry);
            }
            return asQDLValue(QDLStem);
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
        public QDLValue evaluate(QDLValue[] objects, State state) {
            if (!hasJWKS()) {
                throw new IllegalStateException(" No keys have been set.");
            }
            URI well_known = null;
            if (objects.length == 2) {
                try {
                    well_known = URI.create(objects[1].asString());
                } catch (Throwable t) {
                    throw new BadArgException(" The second argument \"" + objects[1] + "\" must be a valid URI.",1);
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
            return asQDLValue(QDLStem);
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
        public QDLValue evaluate(QDLValue[] objects, State state) {
            String token = objects[0].asString();

            JSONObject[] array = JWTUtil.readJWT(token);
            QDLStem QDLStem = new QDLStem();
            QDLStem.fromJSON(array[JWTUtil.HEADER_INDEX]);
            return asQDLValue(QDLStem);
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
        public QDLValue evaluate(QDLValue[] objects, State state) {
            String token = objects[0].asString();

            JSONObject[] array = JWTUtil.readJWT(token);
            QDLStem QDLStem = new QDLStem();
            QDLStem.fromJSON(array[JWTUtil.PAYLOAD_INDEX]);
            return asQDLValue(QDLStem);
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

    public class Create_UUID implements QDLFunction {
        @Override
        public String getName() {
            return CREATE_UUID;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public QDLValue evaluate(QDLValue[] objects, State state) {
            UUID uuid = UUID.randomUUID();
            return asQDLValue(uuid.toString());
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + " create a new uuid.");
            doxx.add("This returns a string.");
            return doxx;
        }
    }

/*    @Override
    public JSONObject serializeToJSON() {
        return null;
    }

    @Override
    public void deserializeFromJSON(JSONObject jsonObject) {

    }*/
}
