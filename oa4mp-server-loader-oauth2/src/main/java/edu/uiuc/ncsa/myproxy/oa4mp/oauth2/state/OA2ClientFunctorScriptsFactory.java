package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.*;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowType;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.jSetClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceConfigurationUtil;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.oauth_2_0.server.scripts.functor.ClientFunctorScriptsFactory;
import edu.uiuc.ncsa.security.util.functor.JFunctor;
import edu.uiuc.ncsa.security.util.functor.JFunctorFactory;
import edu.uiuc.ncsa.security.util.functor.LogicBlock;
import edu.uiuc.ncsa.security.util.functor.logic.jThen;
import edu.uiuc.ncsa.security.util.functor.parser.Script;
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
public class OA2ClientFunctorScriptsFactory<V extends OA2ClientFunctorScripts> extends ClientFunctorScriptsFactory<V> {
    public OA2ClientFunctorScriptsFactory(JSONObject config, JFunctorFactory functorFactory) {
        super(config, functorFactory);
    }


    /**
     * Create the claims sources from the configuration runtime information and set it in the configuration.
     * You must do this before using the sources. Response is never null
     *
     * @param json
     * @param cc
     */
    public void createClaimSource(V cc, JSONObject json) {
        cc.setPreProcessing(new Script(functorFactory, OA2ClientFunctorScriptsUtil.getClaimsPreProcessing(json)));
        cc.setPostProcessing(new Script(functorFactory, OA2ClientFunctorScriptsUtil.getClaimsPostProcessing(json)));
        // Now to get the claim sources. These can be in either the runtime or the pre-processor
        LinkedList<ClaimSource> claimSources = new LinkedList<>();
        extractClaimsSource(cc.getPreProcessing(), json, claimSources);
        extractClaimsSource(cc.getRuntime(), json, claimSources);
        if (claimSources.isEmpty()) {
            claimSources.add(new BasicClaimsSourceImpl());
        }
        cc.setClaimSource(claimSources);
    }

    public void extractClaimsSource(Script script,
                                    JSONObject json,
                                    LinkedList<ClaimSource> claimSources) {
        script.execute();
        if (script.hasHandlers()) {

            List<JFunctor> sources = script.getFunctorMap().get(FlowType.SET_CLAIM_SOURCE.getValue());
            // This is perfectly possible if the claim sources are defined by a conditional and that is not met.
            // Then there are no claim sources and only the most basic claim source is used.
            if (sources != null) {
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
        if (script.hasLogicBlocks()) {


            for (LogicBlock logicBlock : script.getLogicBlocks()) {
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
    }

    public static final String LDAP_DEFAULT = "LDAP"; // header for the basic LDAP
    public static final String HEADER_DEFAULT = "HEADER"; // alias for the header claim source
    public static final String NCSA_DEFAULT = "ncsa-default"; // alias for the NCSA default LDAP claim source
    public static final String FILE_SYSTEM_DEFAULT = "file-system-default"; // alias for the file system claim source

    protected Map<String, ClaimSourceConfiguration> getClaimSourceConfigurations(JSONObject jsonObject) {
        JSONArray array = OA2ClientFunctorScriptsUtil.getClaimSourceConfigurations(jsonObject);
        Map<String, ClaimSourceConfiguration> configs = new HashMap<>();
        ClaimSourceConfigurationUtil claimSourceConfigurationUtil = new ClaimSourceConfigurationUtil(); // for defaults
        LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();
        for (int i = 0; i < array.size(); i++) {
            JSONObject json = array.getJSONObject(i);
            if (claimSourceConfigurationUtil.isInstanceOf(json)) {
                ClaimSourceConfiguration claimSourceConfiguration = new ClaimSourceConfiguration();
                claimSourceConfigurationUtil.fromJSON(claimSourceConfiguration, json);
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
        if (alias.equals(NCSA_DEFAULT)) {
            // This overloads the set_claim_source. The alias is the name of the processor, the configName
            // is actually the search name key (like uid) that LDAP uses to do the search.
            // It is up to the configuration to set the search name key to this as a claims
            // before the claim source gets invoked.
            NCSALDAPClaimSource x = new NCSALDAPClaimSource(configName);
            return x;
        }
        Map<String, OA2ClientFunctorScriptsUtil.SourceEntry> sources = OA2ClientFunctorScriptsUtil.toSourcesMap(json);
        /*
        TODO - handle edge case of no name/alias and single configuration.
         */
        Map<String, ClaimSourceConfiguration> configs = getClaimSourceConfigurations(json);


        ClaimSourceConfiguration config = configs.get(configName);

        if (alias.equals(LDAP_DEFAULT)) {
            return new LDAPClaimsSource((LDAPConfiguration) config, null);
        }

        if (alias.equals(HEADER_DEFAULT)) {
            return new HTTPHeaderClaimsSource(config);
        }
        if (alias.equals(FILE_SYSTEM_DEFAULT)) {
            return new FSClaimSource(config);
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
        Script preProcessing = new Script(functorFactory, OA2ClientFunctorScriptsUtil.getClaimsPreProcessing(json));
        cc.setPreProcessing(preProcessing);
    }

    public void setupPostProcessing(V cc, JSONObject json) {
        Script postProcessing = new Script(functorFactory, OA2ClientFunctorScriptsUtil.getClaimsPostProcessing(json));
        cc.setPostProcessing(postProcessing);
    }


    @Override
    public V get() {
        return (V) new OA2ClientFunctorScripts();
    }
}
