package org.oa4mp.server.admin.oauth2.base;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.ObjectNotFoundException;
import edu.uiuc.ncsa.security.storage.cli.StoreCommands2;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import org.oa4mp.delegation.common.token.impl.TokenUtils;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.qdl_lang.evaluate.SystemEvaluator;
import org.qdl_lang.parsing.QDLInterpreter;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLStem;
import org.qdl_lang.variables.values.QDLValue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static edu.uiuc.ncsa.security.util.cli.CLIDriver.LIST_ALL_METHODS_COMMAND;
import static org.qdl_lang.variables.values.QDLValue.asQDLValue;

/**
 * This class exists because we cannot quite get the dependencies right otherwise. Mostly it is to have access
 * to converters for de/serialization and searching
 * <p>Created by Jeff Gaynor<br>
 * on 7/2/18 at  10:06 AM
 */
public abstract class OA4MPStoreCommands extends StoreCommands2 {

    public OA4MPStoreCommands(CLIDriver driver, String defaultIndent, Store store) throws Throwable {
        super(driver, defaultIndent, store);
        initialize();
    }

    public OA4MPStoreCommands(CLIDriver driver, Store store) throws Throwable {
        super(driver, store);
        initialize();
    }
    @Override
    public void initialize() throws Throwable{
        initHelp();
    }

    public void load(InputLine inputLine){}

    @Override
    public OA2SE getEnvironment() {
        return (OA2SE) super.getEnvironment();
    }

    static final String BASE_32_FLAG = "-32";

    public void encode(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("encode [" + BASE_32_FLAG + "] arg");
            sayi("encode a string using base 64 or base 32. The default is base 64");
            sayi("Note: Enclose your argument in double quotes. You must escape embedded");
            sayi("      double quotes with \\\"");
            say("E.g.");
            sayi("clients>encode \"config \\\" foo \\\"\"\n" +
                    "  Y29uZmlnICIgZm9vICI\n" +
                    "  clients>decode Y29uZmlnICIgZm9vICI\n" +
                    "  config \" foo \"");
            say("note the embedded blanks and quotes are preserved.");
            return;
        }
        boolean doBase32 = inputLine.hasArg(BASE_32_FLAG);
        inputLine.removeSwitch(BASE_32_FLAG);
        // Do surgery so the line acts like the user expects.
        String originalLine = inputLine.getOriginalLine();
        originalLine = originalLine.substring("encode".length()).trim();
        if (doBase32) {
            originalLine = originalLine.substring(BASE_32_FLAG.length()).trim();
        }

        if (originalLine.length() == 0) {
            say("sorry, this needs a single argument.");
            return;
        }
        if (originalLine.startsWith("\"")) {
            originalLine = originalLine.substring(1);
        }
        if (originalLine.endsWith("\"")) {
            originalLine = originalLine.substring(0, originalLine.length() - 1);
        }
        String arg = originalLine.replace("\\\"", "\"");

        if (doBase32) {
            say(TokenUtils.b32EncodeToken(arg));
        } else {
            say(TokenUtils.b64EncodeToken(arg));
        }
    }

    public void decode(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("decode [" + BASE_32_FLAG + "] arg");
            sayi("decode a string using base 64 or base 32. The default is base 64");

            return;
        }
        boolean doBase32 = inputLine.hasArg(BASE_32_FLAG);
        inputLine.removeSwitch(BASE_32_FLAG);
        if (inputLine.getArgCount() != 1) {
            say("sorry, this needs a single argument.");
            return;
        }
        String arg = inputLine.getLastArg();
        if (doBase32) {
            say(TokenUtils.b32DecodeToken(arg));
        } else {
            say(TokenUtils.b64DecodeToken(arg));
        }
    }

    @Override
    public void extraUpdates(Identifiable identifiable, int magicNumber) throws IOException {

    }
/*
search >client_id -r .*123.* -rs A
search >client_id -r .*456.* -rs B
search >client_id -r .*136.* -rs C

search >client_id -r .*123.* -rs X
  got 14 matches.
rs show -range [;5] X
rs show -range -1 X
rs show -range [;5] -attr [client_id,creation_ts] X
rs show -range [-3;0] -attr [client_id,creation_ts] X
rs show -range [2^2;2^3] -attr [client_id,creation_ts] X
 */

    /**
     * Parse lists using QDL. This will remove these are arguments if found.
     *
     * @param inputLine
     * @param key
     * @return
     * @throws Exception
     */
    @Override
    protected List processList(InputLine inputLine, String key) throws Exception {
        // Allow singletons, which requires testing and maybe an exception
        if (!inputLine.hasArg(key) || key==null) {
            return null;
        }
        String originalLine = inputLine.getOriginalLine();
        try {
            int index = Integer.parseInt(inputLine.getNextArgFor(key));
            List<Integer> outList = new ArrayList<Integer>(1);
            outList.add(index);
            inputLine.removeSwitchAndValue(key);
            return outList ;
        } catch (Throwable t) {
            // was not just a number
        }
        String list = extractRawList(inputLine, key);
        String varName = "a.";
        String executableLine = varName + " :=" + list + ";"; // so its a stem
        State state = getState();
        QDLInterpreter interpreter = new QDLInterpreter(null, state);

        try {
            interpreter.execute(executableLine);
            QDLValue o = state.getValue(varName);
            QDLStem qdlStem;
            if (o == null) {
                throw new ObjectNotFoundException("no such value for'" + key + "'");
            }
            qdlStem =  o.asStem();
            // NCSA Sec Lib does not understand QDLValues. Have to convert
            // https://github.com/ncsa/oa4mp/issues/273
            List<Long> outList = new ArrayList<>(qdlStem.getQDLList().size());
            for(QDLValue qdlValue : qdlStem.getQDLList()) {
                outList.add(qdlValue.asLong());
            }
            return outList;
        } catch (Throwable e) {
            // last ditch effort...
            inputLine = new InputLine(originalLine);
            List x = inputLine.getArgList(key);
            if(x != null) {
                return x;
            }
            throw new GeneralException("Error interpreting list:" + e.getMessage(), e);
        }
    }

    public void run_qdl(InputLine inputLine) throws Throwable {
        if(showHelp(inputLine)) {
            say("run_qdl [" + FILE_FLAG + " file_path] [statements]");
            say("Run either a file using QDL's script_load call or directly interpret");
            say(" the rest of the line as parseable QDL. Each store has a separate QDL state and");
            say("interpreter. Since E.g. lists are generally processed as QDL, you can set variables");
            say("and refer to them, or run other QDL.");
            say("This is currently experimental.");
            say();
            say("E.g.");
            say("The rest of the line must be completely valid QDL as all that we do is truncate off the commnd and pass the");
            say("rest to the interpreter:");
            say("run_qdl script_load('vfs#boot/init.qdl', true, -1);");
            return;

        }
        String executableLine = null;
        String file;
        if(inputLine.hasArg(FILE_FLAG)) {
            file = inputLine.getNextArgFor(FILE_FLAG);
            executableLine = SystemEvaluator.LOAD_COMMAND + "(" + file + ");";
        }else{
            String commandName = inputLine.getArg(0);
            int len = commandName.length();
            executableLine = inputLine.getOriginalLine().substring(len);
        }
        QDLInterpreter interpreter = new QDLInterpreter(null, getState());
        try {
            interpreter.execute(executableLine.trim());
        }catch (Throwable t) {
            if(isVerbose()){t.printStackTrace();}
            say("Error interpreting QDL:" + t.getMessage());
        }
    }

@Override
    protected void printIndexHelp(boolean singletonsOnly) {
        super.printIndexHelp(singletonsOnly);
say("and for QDL lists, see");
    say(LIST_ALL_METHODS_COMMAND  + " qdl_lists");
    }

    public State getState() {
        if (state == null) {
            state = new State();
            // Trick, pre-populate with keys, so lists of them don't require escaping.
            MapConverter mapConverter = (MapConverter) getStore().getXMLConverter();
            SerializationKeys serializationKeys = mapConverter.getKeys();
            for (String key : serializationKeys.allKeys()) {
                state.setValue(key, asQDLValue(key));
            }
        }
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }

    State state = null;

    @Override
    public void about(boolean showBanner, boolean showHeader) {
       // No-op since logo is not displayed by components
    }
}
