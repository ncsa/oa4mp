package org.oa4mp.delegation.server.server.claims;

import edu.uiuc.ncsa.security.util.functor.FunctorTypeImpl;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Every {@link ClaimSource} can have a pre or post-processor. These may be either given as JSON objects or as
 * interpretable code. Note that the contract is that if the raw json can be interpreted as a JSON object,
 * then the corresponding property is to be set, otherwise it is to be null.
 * <p>Created by Jeff Gaynor<br>
 * on 7/23/18 at  8:44 AM
 */
public class ClaimSourceConfiguration implements Serializable {
    protected String name = "";

    /**
     * Opaque identifier for uniquely identifying this configuratioin
     *
     * @return
     */
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    protected String id = "";
    protected boolean failOnError = false;
    protected boolean notifyOnFail = false;
    protected boolean enabled = false; // default, since if this is not configured, do not run it.

    /**
     * This is the list of claims from the headers to omit. In other words, this module will reject these out of hand
     * and never return them in a claims object. This is extremely useful in not having existing claims being over-written
     * (which can happen if something like mod_auth_openidc is acting as an intermediary and adding spurious claims.)
     * @return
     */
    public List<String> getOmitList() {
        return omitList;
    }

    public void setOmitList(List<String> omitList) {
        this.omitList = omitList;
    }
     // CIL-513 fix.
    List<String> omitList = new LinkedList<>();

    /**
     * Human readable string that describes this configuration
     *
     * @param name
     */
    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    /**
     * Enable this component. If false then this component will not be used, regardless. Among other things
     * this lets administrators turn off a claim source at the spigot if there is, e.g. a compromise in it,
     * without having to reconfigure the client.
     *
     * @return
     */
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Fail if there is an error, i.e. if the claim source throws an exception, all further processing stops at that point,
     * otherwise, continue, but just don't include the claims from this sournce
     *
     * @return
     */
    public boolean isFailOnError() {
        return failOnError;
    }

    public void setFailOnError(boolean failOnError) {
        this.failOnError = failOnError;
    }

    /**
     * If this claim source has an error, notify the system administrators. This may or may not be an issue,
     * for instance, if the client merely wants to try and retrieve information should it be there,
     * but otherwise it does not matter. At the other end of the spectrum, if the claim source fails
     * it may be an institution-wide issue we need to know about it now.
     *
     * @return
     */

    public boolean isNotifyOnFail() {
        return notifyOnFail;
    }

    public void setNotifyOnFail(boolean notifyOnFail) {
        this.notifyOnFail = notifyOnFail;
    }

    String rawPreProcessor;
    /*
    NOTE in order to cur down on ambiguity, the raw string for the pre and post processors are stored and only
    converter to JSON as needed. This ensure proper serialization to/from storage and ensure that there is not
    a conflict from different versions.
     */


    /**
     * The parseable string for the post processor. These are resolved at runtime because they may rely on the state
     * of the request, such as the current claims and the scopes permitted. This always is set if there is  anything in the configuration.
     * The question is whether it consists of valid JSON or interpretable code.
     *
     * @return
     */
    public String getRawPostProcessor() {
        return rawPostProcessor;
    }

    public void setRawPostProcessor(String rawPostProcessor) {
        this.rawPostProcessor = rawPostProcessor;
    }

    /**
     * The parseable string for the preprocessor. See note for {@link #getRawPostProcessor()}.
     *
     * @return
     */
    public String getRawPreProcessor() {
        return rawPreProcessor;
    }

    public void setRawPreProcessor(String rawPreProcessor) {
        this.rawPreProcessor = rawPreProcessor;
    }

    String rawPostProcessor;
    protected boolean jsonPreProcessorDone = false;
    protected boolean jsonPostProcessorDone = false;

    JSONObject jsonPreProcessing = null;
    JSONObject jsonPostProcessing = null;


    public JSONObject getJSONPostProcessing() {
        if (jsonPostProcessorDone) {
            return jsonPostProcessing;
        }
        jsonPostProcessing = makeProcessor(rawPostProcessor);
        jsonPostProcessorDone = true;
        return jsonPostProcessing;
    }

    public boolean hasJSONPreProcessing() {
        return getJSONPreProcessing() != null;
    }

    public boolean hasJSONPostProcessing() {
        return getJSONPostProcessing() != null;
    }

    /**
     * The <b>json</b> for the pre-processing directives. This has to be done this way since the directives
     * rely on being constructed with the claims at runtime (e.g. for replacement templates).
     *
     * @return
     */
    public JSONObject getJSONPreProcessing() {
        if (jsonPreProcessorDone) {
            return jsonPreProcessing;
        }
        jsonPreProcessing = makeProcessor(rawPreProcessor);
        jsonPreProcessorDone = true;
        return jsonPreProcessing;
    }

    protected JSONObject makeProcessor(String rawProcessor) {
        if (rawProcessor != null && !rawProcessor.isEmpty()) {
            JSONArray array = null;
            try {
                array = JSONArray.fromObject(rawProcessor);
                JSONObject j = new JSONObject();
                j.put(FunctorTypeImpl.OR.getValue(), array);
                return j;
            } catch (Throwable t) {
                // do nothing
            }
            // So it's not an array. See if it's a JSONObject
            try {
                return JSONObject.fromObject(rawProcessor);
            } catch (Throwable t) {
            }
        }
        // do nothing if it is not JSON
        return null;
    }

    Map<String, Object> map = null;

    /**
     * Set a bunch of properties for this configuration object.
     *
     * @param map
     */
    public void setProperties(Map<String, Object> map) {
        this.map = map;
    }

    /**
     * Get all the properties this knows about.
     * @return
     */
    public Map<String, Object> getProperties(){
        return map;
    }
    public Object getProperty(String key) {
        if (map == null || !map.containsKey(key)) {
            return null;
        }
        return map.get(key);
    }

    @Override
    public String toString() {
        return "ClaimSourceConfiguration{" +
                "enabled=" + enabled +
                ", name='" + name + '\'' +
                ", id='" + id + '\'' +
                ", failOnError=" + failOnError +
                ", notifyOnFail=" + notifyOnFail +
                ", omitList=" + omitList +
                '}';
    }

    int retryCount = 1;
    long maxWait = 0L;

    /**
     * How many times to retry connecting.
     * @return
     */
    public int getRetryCount() {
        return retryCount;
    }

    public void setRetryCount(int retryCount) {
        this.retryCount = retryCount;
    }

    /**
     * How long to sleep between connection retries in LDAP
     * @return
     */
    public long getMaxWait() {
        return maxWait;
    }

    public void setMaxWait(long maxWait) {
        this.maxWait = maxWait;
    }
}
