package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.delegation.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.util.cli.InputLine;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * This gives QDL the ability to look into stores such as clients, approvals, etc.
 * programatically. It is designed to be similar to the CLI for OA4MP, hence
 * more or less a take off of {@link edu.uiuc.ncsa.myproxy.oa4mp.server.StoreCommands2}.
 * This class is used by others for accessing a store, so it assumes that the inputs
 * have been checked (e.g. that a method is called with the right value). As such
 * the error handling here is pretty barebones.
 * <p>Created by Jeff Gaynor<br>
 * on 12/17/20 at  4:28 PM
 */
public class QDLStoreAccessor {
    public QDLStoreAccessor(String accessorType, Store store, MyLoggingFacade myLogger) {
        this.accessorType = accessorType;
        this.store = store;
        this.logger = myLogger;
    }
     MyLoggingFacade logger;

    public String getAccessorType() {
        return accessorType;
    }

    public void setAccessorType(String accessorType) {
        this.accessorType = accessorType;
    }

    String accessorType = null;

    public Store getStore() {
        return store;
    }

    public void setStore(Store store) {
        this.store = store;
    }

    Store<Identifiable> store;

    public StemVariable get(Identifier id) {
        return toStem((Identifiable) getStore().get(id));
    }


    /**
     * Save OR update the store from a stem or list of them.
     * @param stemVariable
     * @param doSave
     * @return
     */
    public List<Boolean> saveOrUpdate(StemVariable stemVariable, boolean doSave) {
        List<Boolean> out = new ArrayList<>();
        if (stemVariable.isList()) {
            for (int i = 0; i < stemVariable.size(); i++) {
                Object obj = stemVariable.get(i);
                if (obj instanceof StemVariable) {
                    StemVariable stemVariable1 = (StemVariable) obj;
                    if (!stemVariable1.isList()) {
                        try {
                            if(doSave) {
                                getStore().save(fromStem(stemVariable1));
                            }else{
                                getStore().update(fromStem(stemVariable1));
                            }
                            out.add(Boolean.TRUE);
                        }catch(Throwable t){
                            String msg = t.getMessage();
                            if(t.getCause() != null){
                                msg = t.getCause().getMessage();
                            }
                            warn("Could not "+ (doSave?"save":"update") + " object:" + msg);
                            out.add(Boolean.FALSE);
                        }
                    }else{
                        out.add(Boolean.FALSE);
                    }
                }
            }
        } else {
            getStore().save(fromStem(stemVariable));
            out.add(Boolean.TRUE);

        }
        return out;
    }


    /**
     * Does the same as the {@link edu.uiuc.ncsa.myproxy.oa4mp.server.StoreCommands2#serialize(InputLine)}
     *  Take a stem and convert it to an object then to XML format.
     * @param stem
     * @return
     */
    public String toXML(StemVariable stem) {
        XMLMap c = new XMLMap();
        store.getXMLConverter().toMap(fromStem(stem), c);
        try {
            ByteArrayOutputStream fos = new ByteArrayOutputStream();
            c.toXML(fos);
            fos.flush();
            fos.close();
            return new String(fos.toByteArray());
        } catch (IOException iox) {
            // no way to get an exception from a byte array output stream...
        }
        throw new GeneralException("Could not convert to XML");
    }


    /**
     * Does the same as {@link edu.uiuc.ncsa.myproxy.oa4mp.server.StoreCommands2#deserialize(InputLine)}
     *  Take a string and turn it into an object (in this case, a stem)
     * @param x
     * @return
     */
    public StemVariable fromXML(String x) {
        try {
            ByteArrayInputStream fis = new ByteArrayInputStream(x.getBytes());
            XMLMap map = new XMLMap();
            map.fromXML(fis);
            fis.close();
            Identifiable newId = store.create();
            getConverter().fromMap(map, newId);
            return toStem(newId);
        } catch (IOException iox) {

        }
        throw new GeneralException("Could not convert from XML");
    }

    /**
     * Either
     *
     * @param id
     * @return
     */
    public boolean remove(Identifier id) {
        getStore().remove(id);
        return true;
    }

    public void setMapConverter(StemConverter mapConverter) {
        this.mapConverter = mapConverter;
    }

    StemConverter mapConverter;

    SerializationKeys getStoreKeys() {
        return getConverter().getKeys();
    }

    protected StemConverter getConverter() {
        if (mapConverter == null) {
            // fall back, but it probably should do something else eventually.
            XMLConverter xmlConverter = store.getXMLConverter();
            if (!(xmlConverter instanceof StemConverter)) {
                throw new GeneralException("Internal error: XMLConverter not an instance of StemConverter");
            }
            mapConverter = (StemConverter) xmlConverter;
        }
        return mapConverter;
    }

    /**
     * The size of the store
     *
     * @param includeVersions include versions of items
     * @return
     */
    public Long size(Boolean includeVersions) {
        int x = getStore().size(includeVersions);
        return Long.valueOf(x);
    }

    protected StemVariable toStem(Identifiable identifiable) {
        StemVariable stem = new StemVariable();
        getConverter().toMap(identifiable, stem);
        return stem;
    }

    protected Identifiable fromStem(StemVariable stem) {
        return mapConverter.fromMap(stem, null);
    }

    public StemVariable create(String id) {
        Identifiable newObject = getStore().create();
        if (!StringUtils.isTrivial(id)) {
            newObject.setIdentifier(BasicIdentifier.newID(id));
            if (newObject instanceof OA2ServiceTransaction) {
                // special case if the backing store handles transactions. Otherwise the id and grant are out of whack
                ((OA2ServiceTransaction) newObject).setAuthorizationGrant(new AuthorizationGrantImpl(URI.create(id)));
            }
        }
        return toStem(newObject);
    }

    /**
     * Does a standard search, returning a list of found elements. Note that this may be
     * <i>very</i> long if the query is too general.
     *
     * @param key
     * @param condition
     * @param isregex
     * @return
     */
    public StemVariable search(String key, String condition, Boolean isregex) {
        StemVariable output = new StemVariable();
        List<Identifiable> result = getStore().search(key, condition, isregex);
        List<StemVariable> stems = new ArrayList<>();
        for (Identifiable identifiable : result) {
            stems.add(toStem(identifiable));
        }
        output.addList(stems);
        return output;
    }

    //  store#init('/home/ncsa/dev/csd/config/server-oa2.xml', 'localhost:oa4mp.oa2.mariadb', 'transaction')
    //  t. :=  store#search('temp_token', '.*23.*')
    public StemVariable listKeys() {
        List<String> keys = getStoreKeys().allKeys();
        StemVariable stemVariable = new StemVariable();
        stemVariable.addList(keys);
        return stemVariable;
    }

    /**
     * In a few cases we need an actual {@link Identifiable} object.
     *
     * @param map
     * @return
     */
    protected Identifiable fromXMLMap(XMLMap map) {
        Identifiable identifiable = getStore().create();
        getConverter().fromMap(map, identifiable);
        return identifiable;
    }
    public void warn(String x){
       if(logger == null){
           System.err.println(x);
       }else{
           logger.warn(x);
       }
    }
    public void info(String x){
        if(logger == null){
            System.err.println(x);
        }else{
            logger.info(x);
        }

    }
}
