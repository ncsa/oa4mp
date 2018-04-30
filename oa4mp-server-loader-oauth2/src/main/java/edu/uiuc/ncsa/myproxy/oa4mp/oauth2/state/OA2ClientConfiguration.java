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

    LogicBlocks<? extends LogicBlock> claimsProcessing;

    public void setClaimsProcessing(LogicBlocks<? extends LogicBlock> claimsProcessing) {
        this.claimsProcessing = claimsProcessing;
    }

    public LogicBlocks<? extends LogicBlock> getProcessing() {
        return claimsProcessing;
    }

    public boolean executeProcessing() {
        if (claimsProcessing != null) {
            claimsProcessing.execute();
            return true;
        }
        return false;
    }

    public boolean hasClaimsProcessing(){
        return claimsProcessing!=null & !claimsProcessing.isEmpty();
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
