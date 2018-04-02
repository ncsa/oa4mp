package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.CAFunctorFactory;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.functor.LogicBlock;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.List;
import java.util.Map;

/**
 * After the claims have been created, processing can be applied to them as per configuration.
 * <p>Created by Jeff Gaynor<br>
 * on 3/2/18 at  3:12 PM
 */

public class ClaimsProcessor {
    protected JSONObject config;

    public ClaimsProcessor(JSONObject config) {
        this.config = config;
    }

    protected List<LogicBlock> logicBlocks;

    public Map<String, Object> process(Map<String, Object> claims) {
        ServletDebugUtil.dbg(this, "starting processing");

        if(config == null || config.isEmpty()){
            ServletDebugUtil.dbg(this, "NO configuration, returning.");
            return claims;
        }

        logicBlocks = createLogicBlocks(config, claims);
        ServletDebugUtil.dbg(this, "created " + logicBlocks.size() + " logic blocks.");

        for (LogicBlock logicBlock : logicBlocks) {
            ServletDebugUtil.dbg(this, "currently evaluting logic block " + logicBlock.toString());
            logicBlock.execute();
            ServletDebugUtil.dbg(this, "logic block results = " + logicBlock.getResults());
        }
        executed = true;
        ServletDebugUtil.dbg(this, "Finished processing, returned claims are");
        ServletDebugUtil.dbg(this, claims.toString());

        return claims;
    }

    public boolean isExecuted() {
        return executed;
    }

    /**
     * create the logic blocks for this configuration. It also configures the factory
     * @param configuration
     * @return
     */
    protected List<LogicBlock> createLogicBlocks(JSONObject configuration, Map<String, Object> claims){
        ServletDebugUtil.dbg(this, "config:\n\n" + config.toString(2));
        CAFunctorFactory functorFactory = new CAFunctorFactory(claims);

        JSONArray jsonArray = new JSONArray();
        jsonArray.add(config);
        ServletDebugUtil.dbg(this, "created JSON array:\n\n" + jsonArray.toString(2));

        return functorFactory.createLogicBlock(jsonArray);

    }
    protected boolean executed = false;
}
