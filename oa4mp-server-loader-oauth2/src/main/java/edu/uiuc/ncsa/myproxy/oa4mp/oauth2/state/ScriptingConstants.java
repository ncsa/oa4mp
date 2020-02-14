package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state;

/**
 * Constants related to scripting and running them.
 * <p>Created by Jeff Gaynor<br>
 * on 2/13/20 at  3:15 PM
 */
public interface ScriptingConstants {
    /*
      Execution actions for the SRE = script runtime engine.
     */
    String SRE_NO_EXEC_PHASE = "none";
    String SRE_EXEC_INIT = "init";
    String SRE_PRE_AUTH = "pre_auth";
    String SRE_POST_AUTH = "post_auth";
    String SRE_PRE_AT = "pre_at";
    String SRE_POST_AT = "post_at";
    String SRE_PRE_RT = "pre_rt";
    String SRE_POST_RT = "post_rt";
    String SRE_REQ_CLAIMS = "claims";
    String SRE_REQ_SCOPES = "scopes";
    String SRE_REQ_FLOW_STATES = "flow_states";
    String SRE_REQ_CLIENT_CONFIG = "client_config";
    String SRE_REQ_PHASE = "exec_phase";
    String SRE_REQ_CLAIM_SOURCES = "claim_sources";
    public String[] phases =  {SRE_EXEC_INIT,SRE_PRE_AUTH,SRE_POST_AUTH,SRE_PRE_AT,SRE_POST_AT};

}
