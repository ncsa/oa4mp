package edu.uiuc.ncsa.myproxy.oa4mp.qdl.util;

import edu.uiuc.ncsa.qdl.extensions.JavaModule;
import edu.uiuc.ncsa.qdl.module.Module;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.xml.XMLMissingCloseTagException;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.stream.events.XMLEvent;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/7/20 at  1:24 PM
 */
public class JWTModule extends JavaModule {

    public static final String JWT_COMMANDS_TAG = "jwt_commands";

    public JWTModule() {
    }

    public JWTModule(URI namespace, String alias) {
        super(namespace, alias);
    }

    protected JWTCommands jwtCommands;

    @Override
    public Module newInstance(State state) {
        JWTModule jwtModule = new JWTModule(URI.create("oa2:/qdl/jwt"), "jwt");
        JWTCommands jwtCommands = new JWTCommands(null);
        if (state != null) {
            jwtCommands.setLogger(state.getLogger());
        }
        jwtModule.jwtCommands = jwtCommands;
        funcs = new ArrayList<>();
        funcs.add(jwtCommands.new CreateJWK());
        funcs.add(jwtCommands.new LoadJWK());
        funcs.add(jwtCommands.new KeyInfo());
        funcs.add(jwtCommands.new Create_UUID());
        funcs.add(jwtCommands.new SaveKeys());
        funcs.add(jwtCommands.new CreateJWT());
        funcs.add(jwtCommands.new VerifyJWT());
        funcs.add(jwtCommands.new GetHeader());
        funcs.add(jwtCommands.new GetPayload());
        funcs.add(jwtCommands.new DefaultKey());
        funcs.add(jwtCommands.new SymmKeys());
        jwtModule.addFunctions(funcs);
        vars = new ArrayList<>();
        vars.add(jwtCommands.new TestClaims());
        vars.add(jwtCommands.new TestScopes());
        vars.add(jwtCommands.new TestAudience());
        vars.add(jwtCommands.new TestXAs());
        jwtModule.addVariables(vars);
        if (state != null) {
            jwtModule.init(state);
        }
        return jwtModule;
    }

    @Override
    public void writeExtraXMLElements(XMLStreamWriter xsw) throws XMLStreamException {
        super.writeExtraXMLElements(xsw);
        if (jwtCommands != null && jwtCommands.jwks!=null) {
            xsw.writeStartElement(JWT_COMMANDS_TAG);
            JSONWebKeyUtil.toXML(jwtCommands.jwks, xsw);
            xsw.writeEndElement();
        }
    }

    @Override
    public void readExtraXMLElements(XMLEvent xe, XMLEventReader xer) throws XMLStreamException {
        super.readExtraXMLElements(xe, xer);
        xe = xer.peek();
        while (xer.hasNext()) {
            switch (xe.getEventType()) {
                case XMLEvent.START_ELEMENT:
                    switch (xe.asStartElement().getName().getLocalPart()) {
                        case JWT_COMMANDS_TAG:
                            try {
                                jwtCommands.jwks = JSONWebKeyUtil.fromXML(xer);
                            } catch (Throwable e) {
                                System.out.println("Error: Could not deserialize the JWT module. " + e.getMessage());
                            }
                    }
                    break;
                case XMLEvent.END_ELEMENT:
                    if (xe.asEndElement().getName().getLocalPart().equals(JWT_COMMANDS_TAG)) {
                           return;
                    }
                    break;


            }
            xe = xer.nextEvent();
        }
        throw new XMLMissingCloseTagException(JWT_COMMANDS_TAG);
    }
    List<String> descr = new ArrayList<>();

    @Override
    public List<String> getDescription() {
        if(descr.isEmpty()){
            descr.add("The module for JWT (JSON Web Token) support. This will allow you to create them,");
            descr.add("validate them, create and save keys, etc.");
        }
        return descr;
    }
}
