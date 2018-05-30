package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state;

import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.ClientConfiguration;
import edu.uiuc.ncsa.security.util.functor.LogicBlock;
import edu.uiuc.ncsa.security.util.functor.LogicBlocks;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/16/18 at  4:29 PM
 */
public class OA2ClientConfiguration extends ClientConfiguration {
    public OA2ClientConfiguration() {
        super();
    }

    LogicBlocks<? extends LogicBlock> postProcessing;
    LogicBlocks<? extends LogicBlock> preProcessing;

    public void setPostProcessing(LogicBlocks<? extends LogicBlock> postProcessing) {
        this.postProcessing = postProcessing;
    }
    public void setPreProcessing(LogicBlocks<? extends LogicBlock> preProcessing) {
           this.preProcessing = preProcessing;
       }
    public LogicBlocks<? extends LogicBlock> getPreProcessing() {
        return preProcessing;
    }
    public LogicBlocks<? extends LogicBlock> getPostProcessing() {
        return postProcessing;
    }

    public boolean executePostProcessing() {
        if (postProcessing != null) {
            postProcessing.execute();
            return true;
        }
        return false;
    }

    public boolean executePreProcessing() {
        if (preProcessing != null) {
            preProcessing.execute();
            return true;
        }
        return false;
    }



    public boolean hasPostProcessing(){
        return postProcessing !=null & !postProcessing.isEmpty();
    }
    public boolean hasPreProcessing(){
        return preProcessing !=null & !preProcessing.isEmpty();
    }
    public void setClaimSource(List<ClaimSource> claimSource) {
        this.claimSource = claimSource;
    }

    List<ClaimSource> claimSource;

    public boolean hasClaimSource(){
        return claimSource != null && !claimSource.isEmpty();
    }
    public List<ClaimSource> getClaimSource() {
        return claimSource;
    }

    public boolean isSaved() {
        return saved;
    }

    public void setSaved(boolean saved) {
        this.saved = saved;
    }

    boolean saved=true;
}
