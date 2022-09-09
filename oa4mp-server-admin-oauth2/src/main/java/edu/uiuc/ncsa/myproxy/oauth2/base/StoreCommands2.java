package edu.uiuc.ncsa.myproxy.oauth2.base;

import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.TokenUtils;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.storage.cli.StoreCommands;
import edu.uiuc.ncsa.security.util.cli.CommandLineTokenizer;
import edu.uiuc.ncsa.security.util.cli.InputLine;

import java.util.Vector;

/**
 * This class exists because we cannot quite get the dependencies right otherwise. Mostly it is to have access
 * to converters for de/serialization and searching
 * <p>Created by Jeff Gaynor<br>
 * on 7/2/18 at  10:06 AM
 */
public abstract class StoreCommands2 extends StoreCommands {


    public StoreCommands2(MyLoggingFacade logger, String defaultIndent, Store store) {
        super(logger, defaultIndent, store);
    }

    public StoreCommands2(MyLoggingFacade logger, Store store) {
        super(logger, store);
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

}
