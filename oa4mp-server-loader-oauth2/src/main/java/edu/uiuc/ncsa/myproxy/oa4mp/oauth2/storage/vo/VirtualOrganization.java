package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo;

import edu.uiuc.ncsa.qdl.xml.XMLUtils;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.XMLEvent;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Iterator;

import static edu.uiuc.ncsa.myproxy.oa4mp.qdl.QDLXMLConstants.*;
import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/16/21 at  6:59 AM
 */
public class VirtualOrganization extends IdentifiableImpl {
    public VirtualOrganization(Identifier identifier) {
        super(identifier);
    }

    long created = System.currentTimeMillis();
    String defaultKeyID;
    String discoveryPath;
    String issuer;
    JSONWebKeys jsonWebKeys;
    long lastModified = System.currentTimeMillis();
    String title;
    boolean valid = true;


    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }


    public long getCreated() {
        return created;
    }

    public void setCreated(long created) {
        this.created = created;
    }

    public String getDefaultKeyID() {
        return defaultKeyID;
    }

    public void setDefaultKeyID(String defaultKeyID) {
        this.defaultKeyID = defaultKeyID;
    }

    public String getDiscoveryPath() {
        return discoveryPath;
    }

    public void setDiscoveryPath(String discoveryPath) {
        this.discoveryPath = discoveryPath;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public JSONWebKeys getJsonWebKeys() {
        return jsonWebKeys;
    }

    public void setJsonWebKeys(JSONWebKeys jsonWebKeys) {
        this.jsonWebKeys = jsonWebKeys;
    }

    public long getLastModified() {
        return lastModified;
    }

    public void setLastModified(long lastModified) {
        this.lastModified = lastModified;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public void toXML(XMLStreamWriter xsw) throws XMLStreamException {
        xsw.writeStartElement(VO_ENTRY);
        xsw.writeAttribute(ID_ATTR, getIdentifierString());
        xsw.writeAttribute(VO_CREATED, Long.toString(created));
        xsw.writeAttribute(VO_LAST_MODIFIED, Long.toString(lastModified));
        xsw.writeAttribute(IS_VALID_ATTR, Boolean.toString(valid));
        if (!isTrivial(issuer)) {
            xsw.writeAttribute(ISSUER, issuer);
        }
        if (!isTrivial(discoveryPath)) {
            xsw.writeAttribute(VO_DISCOVERY_PATH, discoveryPath);
        }
        if (!isTrivial(title)) {
            xsw.writeAttribute(VO_TITLE, title);
        }
        if (!isTrivial(defaultKeyID)) {
            xsw.writeAttribute(VO_DEFAULT_KEY, defaultKeyID);
        }
        if(jsonWebKeys != null){
            JSONObject json = JSONWebKeyUtil.toJSON(jsonWebKeys);
            xsw.writeStartElement(VO_JSON_WEB_KEYS);
            // It is base 64 encoded so we don't have to grapple with escaping and such. All we need
            // is that it is faithfully stashed someplace.
            XMLUtils.write(xsw, Base64.encodeBase64String(json.toString().getBytes(StandardCharsets.UTF_8)));
            xsw.writeEndElement(); // close web keys
        }
        xsw.writeEndElement(); // close tag for VO entry
    }

    public void fromXML(XMLEventReader xer) throws XMLStreamException {
        XMLEvent xe = xer.nextEvent();
        doXMLAttributes(xe);
        // process all the attributes
        while (xer.hasNext()) {
            xe = xer.peek();
            switch (xe.getEventType()) {
                case XMLEvent.START_ELEMENT:
                    switch (xe.asStartElement().getName().getLocalPart()) {
                        case VO_JSON_WEB_KEYS:
                            String raw = xe.asCharacters().getData();
                            try {
                                jsonWebKeys = JSONWebKeyUtil.fromJSON(new String(Base64.decodeBase64(raw)));
                            }catch(NoSuchAlgorithmException | InvalidKeySpecException nsa){
                              throw new IllegalStateException("Error creating JSON web keys:\"" + nsa.getMessage() + "\"");
                            }
                            break;
                    } //end inner switch
                    break;
                case XMLEvent.END_ELEMENT:
                    if (xe.asEndElement().getName().getLocalPart().equals(VO_ENTRY)) {
                        return;
                    }
                    break;

            }
            xer.next();

        }
        throw new IllegalStateException("Error: XML file corrupt. No end tag for " + VO_ENTRY);

    }

    private void doXMLAttributes(XMLEvent xe) {

        Iterator iterator = xe.asStartElement().getAttributes(); // Use iterator since it tracks state
        while (iterator.hasNext()) {
            Attribute a = (Attribute) iterator.next();
            String v = a.getValue();
            switch (a.getName().getLocalPart()) {
                case ID_ATTR:
                    setIdentifier(BasicIdentifier.newID(v));
                    break;
                case VO_CREATED:
                    created = Long.parseLong(v);
                    break;
                case VO_LAST_MODIFIED:
                    lastModified = Long.parseLong(v);
                    break;
                case IS_VALID_ATTR:
                    break;
                case ISSUER:
                    issuer = v;
                    break;
                case VO_DEFAULT_KEY:
                    defaultKeyID = v;
                    break;
                case VO_DISCOVERY_PATH:
                    discoveryPath = v;
                    break;
                case VO_TITLE:
                    title = v;
            }
        }
    }
}
