package edu.uiuc.ncsa.oa2.qdl.clc;

import edu.uiuc.ncsa.myproxy.oauth2.tools.ConfigLoaderTool;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CommandLineClient;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientEnvironment;
import edu.uiuc.ncsa.qdl.parsing.IniParserDriver;
import edu.uiuc.ncsa.qdl.variables.QDLStem;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import java.io.File;
import java.io.FileReader;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/19/23 at  3:32 PM
 */
public class QDLCLC extends OA2CommandLineClient {
    public QDLCLC(MyLoggingFacade logger) {
        super(logger);
    }

    @Override
    protected ConfigurationLoader<? extends AbstractEnvironment> figureOutLoader(String fileName, String configName) throws Throwable {
        if (fileName.endsWith(".ini")) {
            IniParserDriver iniParserDriver = new IniParserDriver();
            File file= new File(fileName);
            if(!file.exists()){
                throw new IllegalArgumentException("no such file '" + file.getAbsolutePath() + "'");
            }
            if(!file.isFile()){
                throw new IllegalArgumentException("'" + file.getAbsolutePath() + "' is not a file");
            }
            FileReader fileReader = new FileReader(file);
            QDLStem out = iniParserDriver.parse(fileReader, true);
            fileReader.close();
            QDLConfigLoader<? extends OA2ClientEnvironment> loader = new QDLConfigLoader<>(out, configName);
            return loader;
        }
        ConfigLoaderTool configLoaderTool = new ConfigLoaderTool();
        return configLoaderTool.figureOutClientLoader(fileName, configName, getComponentName());
    }

    public static void main(String[] args) {
        try {
            runnit(args, new QDLCLC(null));
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }
}
