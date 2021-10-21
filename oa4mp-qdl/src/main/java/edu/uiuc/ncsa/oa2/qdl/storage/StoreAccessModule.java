package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.qdl.extensions.JavaModule;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.extensions.QDLVariable;
import edu.uiuc.ncsa.qdl.module.Module;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.xml.XMLMissingCloseTagException;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.stream.events.XMLEvent;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/18/20 at  3:09 PM
 */
public class StoreAccessModule extends JavaModule {


    public StoreAccessModule() {
    }

    public StoreAccessModule(URI namespace, String alias) {
        super(namespace, alias);
    }

    /**
     * This will create the module and store. Then call {@link #doIt(StoreAccessModule, State)}
     * to finish off the setup.
     *
     * @param state
     * @return
     */
    @Override
    public Module newInstance(State state) {
        StoreAccessModule storeAccessModule = new StoreAccessModule(URI.create("oa2:/qdl/store"), "store");
        storeAccessModule.storeFacade = newStoreFacade();
        doIt(storeAccessModule, state);
        return storeAccessModule;
    }

    /**
     * This sets up the module.
     *
     * @param sam
     * @param state
     */
    protected void doIt(StoreAccessModule sam, State state) {
        if (state != null) {
            sam.storeFacade.setLogger(state.getLogger());
        }
        sam.addFunctions(createFList(sam.storeFacade));
        sam.addVariables(createVarList(sam.storeFacade));

    }

    protected StoreFacade storeFacade;

    protected List<QDLVariable> createVarList(StoreFacade sf) {
        List<QDLVariable> vars = new ArrayList<>();
        vars.add(sf.new FacadeHelp());
        vars.add(sf.new StoreTypes());
        return vars;
    }

    protected List<QDLFunction> createFList(StoreFacade sf) {
        List<QDLFunction> functions = new ArrayList<>();
        functions.add(sf.new Create());
        functions.add(sf.new FromXML());
        functions.add(sf.new InitMethod());
        functions.add(sf.new Keys());
        functions.add(sf.new ReadObject());
        functions.add(sf.new Remove());
        functions.add(sf.new SaveObject());
        functions.add(sf.new Search());
        functions.add(sf.new Size());
        functions.add(sf.new ToXML());
        functions.add(sf.new UpdateObject());
        functions.add(sf.new VCreate());
        functions.add(sf.new VGet());
        functions.add(sf.new VGetVersions());
        functions.add(sf.new VRemove());
        functions.add(sf.new VRestore());
    //    functions.add(sf.new Diff());
        return functions;
    }

    public StoreFacade newStoreFacade() {
        return new StoreFacade();
    }

    // XMl stuff
    public static final String STORE_FACADE_TAG = "store_facade";
    public static final String CFG_FILE_TAG = "cfg_file";
    public static final String CFG_NAME_TAG = "cfg_name";
    public static final String STORE_TYPE_TAG = "store_type";

    @Override
    public void writeExtraXMLElements(XMLStreamWriter xsw) throws XMLStreamException {
        super.writeExtraXMLElements(xsw);
        if (storeFacade != null) {
            xsw.writeStartElement(STORE_FACADE_TAG);
            if (!isTrivial(storeFacade.file)) {
                xsw.writeStartElement(CFG_FILE_TAG);
                xsw.writeCData(storeFacade.file);
                xsw.writeEndElement(); // cfg_file
            }
            if (!isTrivial(storeFacade.cfgName)) {
                xsw.writeStartElement(CFG_NAME_TAG);
                xsw.writeCData(storeFacade.cfgName);
                xsw.writeEndElement(); // cfg_name
            }
            if (!isTrivial(storeFacade.storeType)) {
                xsw.writeStartElement(STORE_TYPE_TAG);
                xsw.writeCData(storeFacade.storeType);
                xsw.writeEndElement(); // store_type
            }
            xsw.writeEndElement();// end store facade
        }

    }

    /**
     * Each of the elements inside the  {@link #STORE_FACADE_TAG} has the same structure.
     * This just slogs through that. Assumption is that this is on the start tag of the element
     *
     * @param tag
     * @throws XMLStreamException
     */
    protected String processXML(XMLEventReader xer, String tag) throws XMLStreamException {
        XMLEvent xe = xer.peek();
        String value = null;
        while (xer.hasNext()) {
            switch (xe.getEventType()) {
                case XMLEvent.CHARACTERS:
                    if (!xe.asCharacters().isWhiteSpace()) {
                        value = xe.asCharacters().getData();
                    }
                    break;
                case XMLEvent.END_ELEMENT:
                    if (xe.asEndElement().getName().getLocalPart().equals(tag)) {
                        return value;
                    }
            }
            xe = xer.nextEvent();
        }
        throw new XMLMissingCloseTagException(tag);
    }

    @Override
    public void readExtraXMLElements(XMLEvent xe, XMLEventReader xer) throws XMLStreamException {
        super.readExtraXMLElements(xe, xer);
        // at the start tag already
        while (xer.hasNext()) {
            switch (xe.getEventType()) {
                case XMLEvent.START_ELEMENT:
                    // if store facade is null (e.g. this is a template) skip this part.
                    if (storeFacade != null) {
                        switch (xe.asStartElement().getName().getLocalPart()) {
                            case CFG_FILE_TAG:
                                storeFacade.file = processXML(xer, CFG_FILE_TAG);
                                break;
                            case CFG_NAME_TAG:
                                storeFacade.cfgName = processXML(xer, CFG_NAME_TAG);
                                break;
                            case STORE_TYPE_TAG:
                                storeFacade.storeType = processXML(xer, STORE_TYPE_TAG);
                                break;
                        }
                    }
                    break;
                case XMLEvent.END_ELEMENT:
                    if (xe.asEndElement().getName().getLocalPart().equals(STORE_FACADE_TAG)) {
                        try {
                            if (storeFacade == null) {
                                storeFacade = newStoreFacade(); // get the right type of store facade
                            }
                            storeFacade.doSetup();
                        } catch (Throwable t) {
                            System.out.println("Could not re-initialize store facade for alias " + getAlias());
                        }
                        return;
                    }
            }
            xe = xer.nextEvent();
        }
        throw new XMLMissingCloseTagException(STORE_FACADE_TAG);
    }

    List<String> descr = new ArrayList<>();

    @Override
    public List<String> getDescription() {
        if (descr.isEmpty()) {
            descr.add("Module for accessing OA4MP stores (except permissions, which require their");
            descr.add("own machinery and hence they have their own module.");
            descr.add("All operations are available, such as creating objects and getting");
            descr.add("objects or searches. Note that you will get a stem of the properties ");
            descr.add("for the object. This determines the object. Note that saving the object");
            descr.add("is not an update, i.e., if you remove properties, they will be deleted");
            descr.add("in the store.");
            descr.add("Use.");
            descr.add("1. use module_load(uri, component), e.g. ");
            descr.add("module_load('oa2:/qdl/store', 'clients');");
            descr.add("2. initialize the store");
            descr.add("clients#init('/home/ncsa/dev/csd/config/server-oa2.xml', 'localhost:oa4mp.oa2.mariadb', 'client');");
            descr.add("This returns true if the store intialized ok.");
            descr.add("3. Issue commands, e.g.");
            descr.add("  x. := store#search('client_id', '.*234.*')\n" +
                    "  size(x.)\n" +
                    "4\n");
            descr.add("Indicates that 4 client records were found. The stem contains the");
            descr.add("records themselves and may be substantial.");
            if (storeFacade != null) {
                descr.add("Supported store types are ");
                descr.add(storeFacade.getStoreTypes().toString());

            }
        }
        return descr;
    }
/*
       // Sets up a couple of stores for testing serialization

       module_import('oa2:/qdl/p_store', 'p');
       p#init('/home/ncsa/dev/csd/config/server-oa2.xml', 'localhost:oa4mp.oa2.mariadb', 'permission')

       module_import('oa2:/qdl/store', 'client');
       client#init('/home/ncsa/dev/csd/config/server-oa2.xml', 'localhost:oa4mp.oa2.mariadb', 'client');
       
     */
}
