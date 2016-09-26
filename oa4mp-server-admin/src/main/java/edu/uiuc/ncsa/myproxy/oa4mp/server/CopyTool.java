package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.myproxy.oa4mp.loader.OA4MPConfigurationLoader;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.util.cli.CLITool;
import edu.uiuc.ncsa.security.util.configuration.ConfigUtil;
import org.apache.commons.cli.Options;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/14/13 at  3:15 PM
 */
public class CopyTool extends CLITool {
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
        if (getCommandLine().getOptionValue(SOURCE_CONFIG_NAME_OPTION).equals(getCommandLine().getOptionValue(TARGET_CONFIG_NAME_OPTION))) {
            throw new MyConfigurationException("Error! You have specified that source and target as the same.");
        }
        String fileName = getCommandLine().getOptionValue(cfgFileOption);
        if (fileName == null) {
            fileName = getCommandLine().getOptionValue(SOURCE_CONFIG_FILE_OPTION);
        }

        String configName = getCommandLine().getOptionValue(cfgNameOption);
        sayv("loading configuration \"" + (configName == null ? "(none)" : configName) + "\" from file " + fileName);
        ConfigurationNode node = ConfigUtil.findConfiguration(fileName,
                getCommandLine().getOptionValue(cfgNameOption),
                OA4MPConfigTags.COMPONENT);
        // override the logging in the configuration file, since that might be remote.
        ConfigurationLoader loader = null;
        setConfigurationNode(node);
        try {
            loader = getLoader();
        } catch (Exception e) {
            throw new GeneralException("Error: Could not get loader", e);
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

    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() throws Exception {
        return new OA4MPConfigurationLoader(getConfigurationNode());
    }

    @Override
    protected Options getOptions() {
        Options options = super.getOptions();
        options.addOption(SOURCE_CONFIG_FILE_OPTION, SOURCE_CONFIG_FILE_LONG_OPTION, true, "The full path to the source configuration file.");
        options.addOption(SOURCE_CONFIG_NAME_OPTION, SOURCE_CONFIG_NAME_LONG_OPTION, true, "The source server for the copy operation.");
        options.addOption(TARGET_CONFIG_FILE_OPTION, TARGET_CONFIG_FILE_LONG_OPTION, true, "The full path to the target configuration file.");
        options.addOption(TARGET_CONFIG_NAME_OPTION, TARGET_CONFIG_FILE_LONG_OPTION, true, "The target server for the operation.");
        return options;
    }

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
