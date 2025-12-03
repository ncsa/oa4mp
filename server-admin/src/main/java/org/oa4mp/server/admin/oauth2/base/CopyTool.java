package org.oa4mp.server.admin.oauth2.base;

import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.core.cf.CFXMLConfigurations;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.util.cli.CLITool2;
import org.oa4mp.server.api.OA4MPConfigTags;
import org.oa4mp.server.api.ServiceEnvironmentImpl;
import org.oa4mp.server.loader.oauth2.loader.OA2CFConfigurationLoader;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/14/13 at  3:15 PM
 */
public  class CopyTool extends CLITool2 {

    @Override
        public ConfigurationLoader<? extends AbstractEnvironment> getLoader() throws Exception {
            return new OA2CFConfigurationLoader<>(getCfNode());
        }

    public CopyTool(ServiceEnvironmentImpl srcEnv, ServiceEnvironmentImpl targetEnv) {
        this.srcEnv = srcEnv;
        this.targetEnv = targetEnv;
    }

    CopyExtension copyExtension;


    public CopyExtension getCopyExtension() {
        if(copyExtension == null){
            copyExtension = new CopyExtension();
        }
        return copyExtension;
    }

    public void setCopyExtension(CopyExtension copyExtension) {
        this.copyExtension = copyExtension;
    }

    /**
     * For use when invoked from the command line. The command line arguments will be parsed.
     */
    public CopyTool() {
    }

    public static final String SOURCE_CONFIG_NAME_OPTION = "s";
    public static final String SOURCE_CONFIG_NAME_LONG_OPTION = "sourceConfigName";

    public static final String SOURCE_CONFIG_FILE_OPTION = CONFIG_FILE_OPTION;
    public static final String SOURCE_CONFIG_FILE_LONG_OPTION = CONFIG_FILE_LONG_OPTION;


    public static final String TARGET_CONFIG_FILE_OPTION = "tcfg";
    public static final String TARGET_CONFIG_FILE_LONG_OPTION = "targetConfigFile";
    public static final String TARGET_CONFIG_NAME_OPTION = "t";
    public static final String TARGET_CONFIG_NAME_LONG_OPTION = "targetConfigName";

    ServiceEnvironmentImpl srcEnv;
    ServiceEnvironmentImpl targetEnv;

    public ServiceEnvironmentImpl getSourceEnv() {
        if (srcEnv == null) {
            srcEnv = getEnv(SOURCE_CONFIG_FILE_OPTION, SOURCE_CONFIG_NAME_OPTION);
        }
        return srcEnv;
    }

    public ServiceEnvironmentImpl getTargetEnv() {
        if (targetEnv == null) {
            targetEnv = getEnv(TARGET_CONFIG_FILE_OPTION, TARGET_CONFIG_NAME_OPTION);
        }
        return targetEnv;
    }

    protected ServiceEnvironmentImpl getEnv(String cfgFileOption, String cfgNameOption) {
        if (getInputLine().getNextArgFor(SOURCE_CONFIG_NAME_OPTION).equals(getInputLine().getNextArgFor(TARGET_CONFIG_NAME_OPTION))) {
            throw new MyConfigurationException("Error! You have specified that source and target as the same.");
        }
        String fileName = getInputLine().getNextArgFor(cfgFileOption);
        if (fileName == null) {
            fileName = getInputLine().getNextArgFor(SOURCE_CONFIG_FILE_OPTION);
        }

        String configName = getInputLine().getNextArgFor(cfgNameOption);
        sayv("loading configuration \"" + (configName == null ? "(none)" : configName) + "\" from file " + fileName);
        CFNode node = CFXMLConfigurations.findConfiguration(fileName,
                OA4MPConfigTags.COMPONENT,
                getInputLine().getNextArgFor(cfgNameOption)
                );
        // override the logging in the configuration file, since that might be remote.
        ConfigurationLoader loader = null;
        setCFNode(node);
        try {
            loader = getLoader();
        } catch (Exception e) {
            throw new GeneralException(" Could not get loader", e);
        }
        //new CILogonConfigurationLoader(node, getMyLogger());
        ServiceEnvironmentImpl env = (ServiceEnvironmentImpl) loader.load();
        return env;
    }

    /**
     * Takes in the total number of records processed so far and returns this plus
     * the number of records this call processes.
     *
     * @param totalRecs
     * @return
     */
    protected int doItWithState(int totalRecs) {
        return getCopyExtension().copy(totalRecs);
    }

    @Override
    public void setEnvironment(AbstractEnvironment environment) {
        super.setEnvironment(environment);
        targetEnv = (ServiceEnvironmentImpl) environment;
        srcEnv = (ServiceEnvironmentImpl) environment;
    }

    @Override
    public void doIt() throws Exception {
        long startTime = System.currentTimeMillis();
        int totalRecs = 0;
        int currentRecCount = getSourceEnv().getClientApprovalStore().size();

        // wipe client approvals before clients or SQL databases will throw a foreign key constraint violation.
        totalRecs += currentRecCount;
        sayv("Copying " + currentRecCount + " client approvals...");
        wipeAndCopy(getSourceEnv().getClientApprovalStore(), getTargetEnv().getClientApprovalStore());


        currentRecCount = getSourceEnv().getClientStore().size();
        totalRecs += currentRecCount;
        sayv("Copying " + currentRecCount + " clients...");
        wipeAndCopy(getSourceEnv().getClientStore(), getTargetEnv().getClientStore());

        totalRecs = doItWithState(totalRecs);
        sayv("Done! (" + ((System.currentTimeMillis() - startTime) / 1000.0) + " sec., " + totalRecs + " total items.)");
    }

    @Override
    public String getComponentName() {
        return OA4MPConfigTags.COMPONENT;
    }

/*

    @Override
    protected Options getOptions() {
        Options options = super.getOptions();
        options.addOption(SOURCE_CONFIG_FILE_OPTION, SOURCE_CONFIG_FILE_LONG_OPTION, true, "The full path to the source configuration file.");
        options.addOption(SOURCE_CONFIG_NAME_OPTION, SOURCE_CONFIG_NAME_LONG_OPTION, true, "The source server for the copy operation.");
        options.addOption(TARGET_CONFIG_FILE_OPTION, TARGET_CONFIG_FILE_LONG_OPTION, true, "The full path to the target configuration file.");
        options.addOption(TARGET_CONFIG_NAME_OPTION, TARGET_CONFIG_FILE_LONG_OPTION, true, "The target server for the operation.");
        return options;
    }*/

    @Override
    public void help() {

    }

    public void wipeAndCopy(Store source, Store target) {
        target.clear();
        target.putAll(source);
    }


    @Override
    public void initialize() throws Exception {
//        getConfigurationNode();
    }
}
