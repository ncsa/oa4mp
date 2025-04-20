package org.oa4mp.server.admin.myproxy.oauth2.base;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.ObjectNotFoundException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.storage.cli.StoreCommands;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.util.cli.CommandLineTokenizer;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import org.oa4mp.delegation.common.token.impl.TokenUtils;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.qdl_lang.parsing.QDLInterpreter;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLList;
import org.qdl_lang.variables.QDLStem;

import java.io.IOException;
import java.util.List;
import java.util.Vector;

/**
 * This class exists because we cannot quite get the dependencies right otherwise. Mostly it is to have access
 * to converters for de/serialization and searching
 * <p>Created by Jeff Gaynor<br>
 * on 7/2/18 at  10:06 AM
 */
public abstract class StoreCommands2 extends StoreCommands {

    public StoreCommands2(MyLoggingFacade logger, String defaultIndent, Store store) throws Throwable{
        super(logger, defaultIndent, store);
    }

    public StoreCommands2(MyLoggingFacade logger, Store store)throws Throwable {
        super(logger, store);
    }



    @Override
    public OA2SE getEnvironment() {
        return (OA2SE)super.getEnvironment();
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







    public static void main(String[] args) {
        CommandLineTokenizer CLT = new CommandLineTokenizer();
        String raw = "update -add -json '{\"fnord\":[\"blarf0\",\"blarf1\"]}' /foo:bar";

        Vector v = CLT.tokenize(raw);
        System.out.println(v);
        InputLine inputLine = new InputLine(v);
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
     * @param inputLine
     * @param key
     * @return
     * @throws Exception
     */
    @Override
    protected List processList(InputLine inputLine, String key) throws Exception {
        // Allow singletons, which requires testing and maybe an exception
        if(!inputLine.hasArg(key)){
            return null;
        }
        try{
            int index = Integer.parseInt(inputLine.getNextArgFor(key));
            QDLList qdlList = new QDLList();
            qdlList.add(index);
            inputLine.removeSwitchAndValue(key);
            return qdlList;
        }catch(Throwable t){
            // was not just a number
        }
        String originalLine = inputLine.getOriginalLine();
        int startKey = originalLine.indexOf(key);
        int endListIndex = originalLine.indexOf("]",startKey);
        int startListIndex = originalLine.indexOf("[",startKey);
        String list = originalLine.substring(startListIndex,endListIndex+1);
        if(list.isEmpty()){
            throw new ObjectNotFoundException("no list was found");
        }
        // clean up
        String newOL = originalLine.substring(0, startKey) + " " + originalLine.substring(endListIndex+1);
        inputLine.setOriginalLine(newOL);
        inputLine.reparse();
        State state = getState();
        QDLInterpreter interpreter = new QDLInterpreter(null, state);

        try {
            interpreter.execute("a.:=" + list + ";");
            Object o = state.getValue("a.");
            QDLStem qdlStem;
            if(o instanceof QDLStem){
                qdlStem = (QDLStem)o;
                return qdlStem.getQDLList();
            }else{
                return null;
            }
        } catch (Throwable e) {
            throw new GeneralException("Error interpreting list:" + e.getMessage(), e);
        }
    }

    public State getState() {
        if(state == null){
            state = new State();
            // Trick, pre-populate with keys
            MapConverter mapConverter = (MapConverter)getStore().getXMLConverter();
            SerializationKeys serializationKeys = mapConverter.getKeys();
            for(String key : serializationKeys.allKeys()){
                state.setValue(key, key);
            }
        }
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }

    State state = null;
}
