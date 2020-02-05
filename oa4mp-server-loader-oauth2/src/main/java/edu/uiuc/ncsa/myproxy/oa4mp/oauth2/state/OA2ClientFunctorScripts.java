package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state;

import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.scripts.functor.ClientFunctorScripts;
import edu.uiuc.ncsa.security.util.functor.parser.Script;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/16/18 at  4:29 PM
 */
public class OA2ClientFunctorScripts extends ClientFunctorScripts {
    public OA2ClientFunctorScripts() {
        super();
    }

    Script postProcessing;
    Script preProcessing;

    public void setPostProcessing(Script postProcessing) {
        this.postProcessing = postProcessing;
    }
    public void setPreProcessing(Script preProcessing) {
           this.preProcessing = preProcessing;
       }
    public Script getPreProcessing() {
        return preProcessing;
    }
    public Script getPostProcessing() {
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
        return postProcessing !=null;
    }
    public boolean hasPreProcessing(){
        return preProcessing !=null ;
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

    @Override
    public boolean executeRuntime() {
       return  super.executeRuntime();
    }
}
