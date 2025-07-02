package org.oa4mp.server.qdl.clc;

import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import org.oa4mp.client.loader.OA2ClientEnvironment;
import org.oa4mp.server.admin.oauth2.tools.ConfigLoaderTool;
import org.oa4mp.server.admin.oauth2.tools.OA2CommandLineClient;
import org.oa4mp.server.qdl.CLC;
import org.qdl_lang.parsing.IniParserDriver;
import org.qdl_lang.variables.QDLStem;

import java.io.File;
import java.io.FileReader;

/**
 * This is the extension of the {@link OA2CommandLineClient} that is able to read QDL configuration files. The
 * QDL modules is {@link CLC}.
 * <p>Created by Jeff Gaynor<br>
 * on 12/19/23 at  3:32 PM
 */
public class QDLCLC extends OA2CommandLineClient {
    public QDLCLC(CLIDriver driver) {
        super(driver);
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
            QDLCLC qdlclc = new QDLCLC(null);
           setInstance(qdlclc);
            qdlclc.runnit(args, qdlclc);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    protected void banner(){
          bannerTimes();
    }
    protected void bannerLarge(){
        say("\n" +
                "                                                                                        \n" +
                "  ,ad8888ba,    88888888ba,    88                ,ad8888ba,   88           ,ad8888ba,   \n" +
                " d8\"'    `\"8b   88      `\"8b   88               d8\"'    `\"8b  88          d8\"'    `\"8b  \n" +
                "d8'        `8b  88        `8b  88              d8'            88         d8'            \n" +
                "88          88  88         88  88              88             88         88             \n" +
                "88          88  88         88  88              88             88         88             \n" +
                "Y8,    \"88,,8P  88         8P  88              Y8,            88         Y8,            \n" +
                " Y8a.    Y88P   88      .a8P   88               Y8a.    .a8P  88          Y8a.    .a8P  \n" +
                "  `\"Y8888Y\"Y8a  88888888Y\"'    88888888888       `\"Y8888Y\"'   88888888888  `\"Y8888Y\"'   \n" +
                "                                                                                        \n" +
                "                                                                                        \n");
    }
    protected void bannerDotMatrix(){
        say("\n" +
                "\n" +
                "___oooo____oooooo____oo____________oooo___oo_________oooo___\n" +
                "_oo____oo__oo____oo__oo__________oo____oo_oo_______oo____oo_\n" +
                "oo______oo_oo_____oo_oo_________oo________oo______oo________\n" +
                "oo___o__oo_oo_____oo_oo_________oo________oo______oo________\n" +
                "_oo___ooo__oo____oo__oo__________oo____oo_oo_______oo____oo_\n" +
                "___oooo_o__oooooo____ooooooo_______oooo___ooooooo____oooo___\n" +
                "_________oo_________________________________________________\n" +
                "\n");
    }
    protected void bannerTimes(){
        say("\n" +
                "\n" +
                "  .oooooo.      oooooooooo.   ooooo               .oooooo.   ooooo          .oooooo.   \n" +
                " d8P'  `Y8b     `888'   `Y8b  `888'              d8P'  `Y8b  `888'         d8P'  `Y8b  \n" +
                "888      888     888      888  888              888           888         888          \n" +
                "888      888     888      888  888              888           888         888          \n" +
                "888      888     888      888  888              888           888         888          \n" +
                "`88b    d88b     888     d88'  888       o      `88b    ooo   888       o `88b    ooo  \n" +
                " `Y8bood8P'Ybd' o888bood8P'   o888ooooood8       `Y8bood8P'  o888ooooood8  `Y8bood8P'  \n" +
                "                                                                                       \n" +
                "                                                                                       \n" +
                "                                                                                       \n" +
                "\n");
    }
}
