package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.CommonCommands;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONObject;

/**
 * A class that allows an admin to create a client configuration from the command line and store it to a file.
 * <p>Created by Jeff Gaynor<br>
 * on 12/18/19 at  5:40 PM
 */
public class ClientCfgCreator extends CommonCommands {
    @Override
    public String getPrompt() {
        return "cfg>";
    }

    public ClientCfgCreator(MyLoggingFacade logger) {
        super(logger);
    }

    public static void main(String[] args){
         ClientCfgCreator clientCfgCreator = new ClientCfgCreator(new MyLoggingFacade(ClientCfgCreator.class.getName()));
         try {
             clientCfgCreator.doIt();
         }catch(Throwable t){
             t.printStackTrace();
         }
    }
    JSONObject config;
    public void doIt() throws Throwable{
        config = new JSONObject();

    }
    public void edit_comments(InputLine inputLine) throws Exception{

    }
}
