package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.BasicClaimsSourceImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.HTTPHeaderClaimsSource;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.LDAPClaimsSource;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowType;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.jSetClaimSource;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceConfigurationUtil;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.ClientConfigurationFactory;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.util.functor.JFunctor;
import edu.uiuc.ncsa.security.util.functor.JFunctorFactory;
import edu.uiuc.ncsa.security.util.functor.LogicBlock;
import edu.uiuc.ncsa.security.util.functor.LogicBlocks;
import edu.uiuc.ncsa.security.util.functor.logic.jThen;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/17/18 at  2:51 PM
 */
public class OA2ClientConfigurationFactory<V extends OA2ClientConfiguration> extends ClientConfigurationFactory<V> {
    public OA2ClientConfigurationFactory(JFunctorFactory functorFactory) {
        super(functorFactory);
    }

    @Override
    public V newInstance(JSONObject json) {
        V v = super.newInstance(json);
        v.setSaved(OA2ClientConfigurationUtil.isSaved(json));
        return v;
    }

    /**
     * Create the claims sources from the configuration runtime information and set it in the configuration.
     * You must do this before using the sources.
     *
     * @param json
     * @param cc
     */
    public void createClaimSource(V cc, JSONObject json) {
        cc.setPreProcessing(functorFactory.createLogicBlock(OA2ClientConfigurationUtil.getClaimsPreProcessing(json)));
        cc.setPostProcessing(functorFactory.createLogicBlock(OA2ClientConfigurationUtil.getClaimsPostProcessing(json)));
        // Now to get the claim sources. These can be in either the runtime or the pre-processor
        LinkedList<ClaimSource> claimSources = new LinkedList<>();
        extractClaimsSource(cc.getPreProcessing(), json, claimSources);
        extractClaimsSource(cc.getRuntime(), json, claimSources);
        if (claimSources.isEmpty()) {
            claimSources.add(new BasicClaimsSourceImpl());
        }
        cc.setClaimSource(claimSources);
    }

    public void extractClaimsSource(LogicBlocks<? extends LogicBlock> logicBlocks,
                                    JSONObject json,
                                    LinkedList<ClaimSource> claimSources) {
        for (LogicBlock logicBlock : logicBlocks) {

            logicBlock.execute();
            jThen consequent = null;
            if (logicBlock.isIfTrue()) {
                consequent = logicBlock.getThenBlock();
            } else {
                consequent = logicBlock.getElseBlock();
            }
            // note that an if block with no explicit else will result in a null consequent, therefore, if the
            // else block is null, do not try to figure out a specialized claim source.
            if (consequent != null && consequent.getFunctorMap().containsKey(FlowType.SET_CLAIM_SOURCE.getValue())) {
                List<JFunctor> sources = consequent.getFunctorMap().get(FlowType.SET_CLAIM_SOURCE.getValue());
                for (JFunctor source : sources) {
                    jSetClaimSource jSetClaimSource = (jSetClaimSource) source;

                    String alias = (String) jSetClaimSource.getArgs().get(0);
                    String configurationName = (String) jSetClaimSource.getArgs().get(1);
                    ClaimSource claimSource = setupClaimSource(alias, configurationName, json);
                    if (claimSource != null) {
                        claimSources.add(claimSource);
                    }
                }
            }
        }
    }

    public static final String LDAP_DEFAULT = "LDAP";
    public static final String HEADER_DEFAULT = "HEADER";

    protected Map<String, ClaimSourceConfiguration> getClaimSourceConfigurations(JSONObject jsonObject) {
        DebugUtil.dbg(this, "Starting claim source configuration.");

        JSONArray array = OA2ClientConfigurationUtil.getClaimSourceConfigurations(jsonObject);
        Map<String, ClaimSourceConfiguration> configs = new HashMap<>();
        ClaimSourceConfigurationUtil claimSourceConfigurationUtil = new ClaimSourceConfigurationUtil(); // for defaults
        LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();
        for (int i = 0; i < array.size(); i++) {
            JSONObject json = array.getJSONObject(i);
            DebugUtil.dbg(this, "json type = " + json.getClass().getCanonicalName());
            if (claimSourceConfigurationUtil.isInstanceOf(json)) {
                DebugUtil.dbg(this, "This is a configuration object");
                ClaimSourceConfiguration claimSourceConfiguration = new ClaimSourceConfiguration();
                claimSourceConfigurationUtil.fromJSON(claimSourceConfiguration, json);
                DebugUtil.dbg(this, ".getClaimsSourceConfigurations: putting configuration object name=" +
                        claimSourceConfiguration.getName() + ", id=" + claimSourceConfiguration.getId());
                String key = claimSourceConfiguration.getId();
                // use the ID to locate the item, not the name. The name should generally only be used for display
                if (key == null || key.length() == 0) {
                    key = claimSourceConfiguration.getName();
                }
                configs.put(key, claimSourceConfiguration);
            }
            if (ldapConfigurationUtil.isLDAPCOnfig(json)) {
                LDAPConfiguration c = ldapConfigurationUtil.fromJSON(json);
                String key = c.getId();
                // use the ID to locate the item, not the name. The name should generally only be used for display
                if (key == null || key.length() == 0) {
                    key = c.getName();
                }
                configs.put(key, c);
            }
        }
        return configs;
    }


    /**
     * Setup the claim sources from the configuration given the alias of the source to use and the name of the configuration
     * to use.
     *
     * @param alias
     * @param configName
     * @param json       - the TOP LEVEL configuration object
     * @return
     */
    protected ClaimSource setupClaimSource(String alias, String configName, JSONObject json) {
        DebugUtil.dbg(this, ".setupClaimSource. alias=" + alias + ", configName=" + configName + ", json=" + (json==null?"none":json.toString(2)));

        Map<String, OA2ClientConfigurationUtil.SourceEntry> sources = OA2ClientConfigurationUtil.toSourcesMap(json);
        /*
        TODO - handle edge cases of no name/alias and single configuration.
         */
        Map<String, ClaimSourceConfiguration> configs = getClaimSourceConfigurations(json);

        ClaimSourceConfiguration config = configs.get(configName);
        DebugUtil.dbg(this, "configuration found from config name=" + config.toString());
        if (alias.equals(LDAP_DEFAULT)) {
            DebugUtil.dbg(this, "Setting Claim Source to LDAP as per configuration");
            LDAPClaimsSource x = new LDAPClaimsSource((LDAPConfiguration) config, null);
            return x;
        }

        if (alias.equals(HEADER_DEFAULT)) {
            DebugUtil.dbg(this, "Setting up header default.");
            ClaimSource source = new HTTPHeaderClaimsSource();
            source.setConfiguration(config);
        }
        if (!sources.containsKey(alias)) {
            throw new IllegalArgumentException("Error:\"" + alias + "\" has not been registered as a claim source");
        }

        ClaimSource claimSource = null;
        try {
            String x = sources.get(alias).className;
            claimSource = (ClaimSource) Class.forName(x).newInstance();
            claimSource.setConfiguration(config);
            // If finding the class fails for any reason, return a null. Other components should check for a null and
            // discard it if there is one.
        } catch (InstantiationException e) {
            claimSource = null;
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            claimSource = null;
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            claimSource = null;
            e.printStackTrace();
        }
        return claimSource;

    }

    public void setupPreProcessing(V cc, JSONObject json) {
        JSONObject jsonObject = OA2ClientConfigurationUtil.getClaimsPreProcessing(json);
        LogicBlocks<? extends LogicBlock> preProcessing;
        preProcessing = functorFactory.createLogicBlock(jsonObject);
        cc.setPreProcessing(preProcessing);

    }

    public void setupPostProcessing(V cc, JSONObject json) {

        JSONObject jsonObject = OA2ClientConfigurationUtil.getClaimsPostProcessing(json);
        LogicBlocks<? extends LogicBlock> postProcessing;
        postProcessing = functorFactory.createLogicBlock(jsonObject);
        cc.setPostProcessing(postProcessing);
    }

    @Override
    public V get() {
        return (V) new OA2ClientConfiguration();
    }
}
