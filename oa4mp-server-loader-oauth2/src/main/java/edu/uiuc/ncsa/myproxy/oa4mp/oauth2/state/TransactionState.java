package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowStates2;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import net.sf.json.JSONObject;

/**
 * This is a container for mutable state per transaction.
 * <p>Created by Jeff Gaynor<br>
 * on 4/10/18 at  1:10 PM
 */
public class TransactionState {
    public static String STATE_TAG = "state";
    public static String FLOW_STATE_TAG = "flow_state";
    public FlowStates2 getFlowStates() {
        return flowStates;
    }

    public void setFlowStates(FlowStates2 flowStates) {
        this.flowStates = flowStates;
    }

    FlowStates2 flowStates;

    /**
     * The ID token once it has been created.
     * @return
     */
    public JSONObject getIdToken() {
        if(idToken == null){
            idToken = new JSONObject();
        }
        return idToken;
    }

    public void setIdToken(JSONObject idToken) {
        this.idToken = idToken;
    }

    JSONObject idToken;

    public JSONObject toJSON(){
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(STATE_TAG,comment);
        if(flowStates != null) {
            jsonObject.put(FLOW_STATE_TAG, flowStates.toJSON());
        }
        if(idToken != null){
            jsonObject.put(OA2Constants.ID_TOKEN, idToken);
        }
        return jsonObject;
    }

    public void fromJSON(JSONObject jsonObject){
         if(jsonObject.containsKey(STATE_TAG)){
             setComment(jsonObject.getString(STATE_TAG));
         }
        if(jsonObject.containsKey(FLOW_STATE_TAG)){

        }
        if(jsonObject.containsKey(OA2Constants.ID_TOKEN)){
            idToken = jsonObject.getJSONObject(OA2Constants.ID_TOKEN);
        }
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    String comment = "transaction state object";
}
