package org.oa4mp.server.loader.oauth2.state;

import org.oa4mp.delegation.server.server.claims.ClaimSource;
import org.oa4mp.delegation.server.server.scripts.functor.ClientFunctorScripts;
import edu.uiuc.ncsa.security.util.functor.parser.FunctorScript;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/16/18 at  4:29 PM
 */
public class OA2ClientFunctorScripts extends ClientFunctorScripts {
    public OA2ClientFunctorScripts() {
        super();
    }

    FunctorScript postProcessing;
    FunctorScript preProcessing;

    public void setPostProcessing(FunctorScript postProcessing) {
        this.postProcessing = postProcessing;
    }
    public void setPreProcessing(FunctorScript preProcessing) {
           this.preProcessing = preProcessing;
       }
    public FunctorScript getPreProcessing() {
        return preProcessing;
    }
    public FunctorScript getPostProcessing() {
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

    /**
     * This is antiquated and is being changed to just return true. The machinery this was to support
     * has been replaced. Just save the configuration like any other.
     * @return
     */
 /*   public boolean isSaved() {
        return true;
    }*/

/*    public void setSaved(boolean saved) {
        this.saved = saved;
    }*/

  //  boolean saved=true;

    @Override
    public boolean executeRuntime() {
       return  super.executeRuntime();
    }
}
