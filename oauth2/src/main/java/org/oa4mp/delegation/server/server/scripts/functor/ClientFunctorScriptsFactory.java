package org.oa4mp.delegation.server.server.scripts.functor;

import edu.uiuc.ncsa.security.util.functor.JFunctorFactory;
import edu.uiuc.ncsa.security.util.functor.parser.FunctorScript;
import edu.uiuc.ncsa.security.util.scripting.ScriptSetFactory;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/5/20 at  2:16 PM
 */
public class ClientFunctorScriptsFactory<V extends ClientFunctorScripts> extends ScriptSetFactory<V> {

    public ClientFunctorScriptsFactory(JSONObject config,
                                       JFunctorFactory functorFactory) {
        super(config);
        this.functorFactory = functorFactory;
    }

    protected JFunctorFactory functorFactory;


    /**
     * Create a new {@link ClientFunctorScripts}.
     *
     * @return
     */
    public V newInstance() {
        V cc = get();
        cc.setRuntime(new FunctorScript(functorFactory, ClientFunctorScriptsUtil.getRuntime(getConfig())));
        return cc;
    }

    /**
     * Note the sequence here. This provides an uninitiailized script. The {@link #newInstance()}
     * populates this, so even though this is a provider, generally you want to call
     * {@link #newInstance()}.
     *
     * @return
     */
    @Override
    public V get() {
        return (V) new ClientFunctorScripts();
    }
}
