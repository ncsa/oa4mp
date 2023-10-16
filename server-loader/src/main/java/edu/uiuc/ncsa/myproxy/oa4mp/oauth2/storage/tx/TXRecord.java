package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.qdl.xml.XMLConstants;
import edu.uiuc.ncsa.qdl.xml.XMLUtilsV2;
import edu.uiuc.ncsa.security.core.DateComparable;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.XMLEvent;
import java.net.URI;
import java.util.*;

import static edu.uiuc.ncsa.myproxy.oa4mp.qdl.QDLXMLConstants.*;
import static edu.uiuc.ncsa.qdl.xml.XMLUtils.readStemAsStrings;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  8:54 AM
 */
public class TXRecord extends IdentifiableImpl implements Identifiable, Cloneable, DateComparable {
    /*
    Note that this should not be serialized since it is really just the date form of the issued at attribute
     */
    @Override
    public Date getCreationTS() {
        if (createdAt == null) {

            createdAt = new Date(getIssuedAt());
        }
        return createdAt;
    }

    Date createdAt = null;

    public TXRecord(Identifier identifier) {
        super(identifier);
    }

    /**
     * The actual token (including any encodings, signatures etc.) returned to the user.
     * @return
     */
    public String getStoredToken() {
        return storedToken;
    }

    public void setStoredToken(String storedToken) {
        this.storedToken = storedToken;
    }

    String storedToken = null;

    /**
     * The TXRecord that was this TXRecord updates. In a token exchange, this is the TXRecord
     * of the last token. If this is null, the token was updated directly from the transaction
     * and that should be used.
     * @return
     */
    public TXRecord getPreviousTXR() {
        return previousTXR;
    }

    public void setPreviousTXR(TXRecord previousTXR) {
        this.previousTXR = previousTXR;
    }

    TXRecord previousTXR = null;

    /**
     * The un-encoded token {@link #getStoredToken()}. In JWTs this is the payload (for header.payload.signature).
     * @return
     */
    public JSONObject getToken() {
        return token;
    }

    public void setToken(JSONObject token) {
        this.token = token;
    }

    JSONObject token = null;
    public boolean hasToken(){
        return token!=null;
    }
    public boolean hasPreviousTX(){
        return previousTXR!=null;
    }

    public Identifier getParentID() {
        return parentID;
    }

    public void setParentID(Identifier parentID) {
        this.parentID = parentID;
    }

    public long getLifetime() {
        return lifetime;
    }

    public void setLifetime(long lifetime) {
        this.lifetime = lifetime;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(long issuedAt) {
        this.issuedAt = issuedAt;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(long expiresAt) {
        this.expiresAt = expiresAt;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public List<String> getScopes() {
        return scopes;
    }

    /**
     * The requested token type from the TX request.
     *
     * @return
     */
    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    /**
     * Convenience method. Just got tired of translating this
     *
     * @param newScopes
     */
    public void setScopes(Collection<String> newScopes) {
        scopes = new ArrayList<>();
        scopes.addAll(newScopes);
    }

    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }

    public boolean hasAudience() {
        return audience != null && !audience.isEmpty();
    }

    public List<String> getAudience() {
        return audience;
    }

    public void setAudience(List<String> audience) {
        this.audience = audience;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public List<URI> getResource() {
        return resource;
    }

    public void setResource(List<URI> resource) {
        this.resource = resource;
    }

    public boolean hasResources() {
        return resource != null && !resource.isEmpty();
    }

    public boolean hasScopes() {
        return scopes != null && !scopes.isEmpty();
    }

    String tokenType;
    List<String> audience;
    long expiresAt = System.currentTimeMillis();
    long lifetime = 0L;
    long issuedAt = System.currentTimeMillis();
    String issuer;
    Identifier parentID;
    List<String> scopes;
    List<URI> resource;
    boolean valid;

    public OA2Client getErsatzClient() {
        return ersatzClient;
    }

    public void setErsatzClient(OA2Client ersatzClient) {
        this.ersatzClient = ersatzClient;
    }

    OA2Client ersatzClient;
    /**
     * This and {@link #fromXML(XMLEventReader)} are needed for QDL state storage.
     *
     * @param xsw
     * @throws XMLStreamException
     */
    public void toXML(XMLStreamWriter xsw) throws XMLStreamException {
        // Note that the creation TS is just the issued at value converted
        // to a date, so do not serialize the creation TS.
        xsw.writeStartElement(TX_RECORD);
        xsw.writeAttribute(XMLConstants.SERIALIZATION_VERSION_TAG, XMLConstants.VERSION_2_0_TAG);
        xsw.writeAttribute(ID_ATTR, getIdentifierString());
        xsw.writeAttribute(EXPIRES_AT_ATTR, Long.toString(expiresAt));
        xsw.writeAttribute(LIFETIME_ATTR, Long.toString(lifetime));
        xsw.writeAttribute(ISSUED_AT_ATTR, Long.toString(issuedAt));
        xsw.writeAttribute(IS_VALID_ATTR, Boolean.toString(valid));
        if(!StringUtils.isTrivial(storedToken)){
            xsw.writeAttribute(STORED_TOKEN, storedToken);
        }
        if (!StringUtils.isTrivial(issuer)) {
            xsw.writeAttribute(ISSUER, issuer);
        }
        if (!StringUtils.isTrivial(tokenType)) {
            xsw.writeAttribute(TOKEN_TYPE, tokenType);
        }
        if (getParentID() != null) {
            xsw.writeAttribute(PARENT_ID, getParentID().toString());
        }
        if (scopes != null && !scopes.isEmpty()) {
            xsw.writeStartElement(SCOPES);
            XMLUtilsV2.toCDATA(xsw, scopes);
            //XMLUtils.write(xsw, scopes);
            xsw.writeEndElement(); // close scopes
        }
        if (audience != null && !audience.isEmpty()) {
            xsw.writeStartElement(AUDIENCE);
            XMLUtilsV2.toCDATA(xsw, audience);
            //XMLUtils.write(xsw, audience);
            xsw.writeEndElement(); // close audience
        }

        if (resource != null && !resource.isEmpty()) {
            xsw.writeStartElement(RESOURCES);
            // resources are all URIs so convert to strings or JSON does very nasty things
            List<String> ll = new ArrayList<>();
            for (URI x : resource) {
                ll.add(x.toString());
            }
            XMLUtilsV2.toCDATA(xsw, ll);
            //XMLUtils.write(xsw, resource);
            xsw.writeEndElement(); // close scopes
        }

        xsw.writeEndElement(); // close tag for TX record
    }

    public void fromXML(XMLEventReader xer) throws XMLStreamException {
        XMLEvent xe = xer.nextEvent();
        // process all the attributes
        String versionNumber = doXMLAttributes(xe);

        switch (versionNumber) {
            case XMLConstants.VERSION_2_0_TAG:
                fromXMLNEW(xer);
                break;
            default:
                fromXMLOLD(xer);
        }
    }

    protected void fromXMLOLD(XMLEventReader xer) throws XMLStreamException {
        XMLEvent xe;
        while (xer.hasNext()) {
            xe = xer.peek();
            JSONArray j;
            switch (xe.getEventType()) {
                case XMLEvent.START_ELEMENT:
                    switch (xe.asStartElement().getName().getLocalPart()) {
                        case AUDIENCE:
                            audience = readStemAsStrings(xer);
                            break;
                        case SCOPES:
                            xer.nextEvent(); // reposition the cursor
                            scopes = readStemAsStrings(xer);
                            break;
                        case RESOURCES:
                            List<String> ll = readStemAsStrings(xer);
                            resource = new ArrayList<URI>();
                            for (String s : ll) {
                                resource.add(URI.create(s));
                            }
                            break;
                    }
                    break;
                case XMLEvent.END_ELEMENT:
                    if (xe.asEndElement().getName().getLocalPart().equals(TX_RECORD)) {
                        return;
                    }
                    break;
            }
            xer.next();
        }
        throw new IllegalStateException("Error: XML file corrupt. No end tag for " + TX_RECORD);


    }

    protected void fromXMLNEW(XMLEventReader xer) throws XMLStreamException {
        XMLEvent xe;
/*
        // process all the attributes
        doXMLAttributes(xe);
*/
        while (xer.hasNext()) {
            xe = xer.peek();
            JSONArray j;
            switch (xe.getEventType()) {
                case XMLEvent.START_ELEMENT:
                    switch (xe.asStartElement().getName().getLocalPart()) {
                        case AUDIENCE:
                            j = JSONArray.fromObject(XMLUtilsV2.getText(xer, AUDIENCE));
                            audience = new ArrayList<>();
                            audience.addAll(j);
                            //audience = readStemAsStrings(xer);
                            break;
                        case SCOPES:
                            j = JSONArray.fromObject(XMLUtilsV2.getText(xer, SCOPES));
                            scopes = new ArrayList<>();
                            scopes.addAll(j);
                            //scopes = readStemAsStrings(xer);
                            break;
                        case RESOURCES:
                            j = JSONArray.fromObject(XMLUtilsV2.getText(xer, RESOURCES));
                            List<String> ll = new ArrayList<>();
                            ll.addAll(j);
                            //List<String> ll = readStemAsStrings(xer);
                            resource = new ArrayList<URI>();
                            for (String s : ll) {
                                resource.add(URI.create(s));
                            }
                            break;
                    }
                    break;
                case XMLEvent.END_ELEMENT:
                    if (xe.asEndElement().getName().getLocalPart().equals(TX_RECORD)) {
                        return;
                    }
                    break;
            }
            xer.next();
        }
        throw new IllegalStateException("Error: XML file corrupt. No end tag for " + TX_RECORD);

    }

    private String doXMLAttributes(XMLEvent xe) {
        String versionNumber = "";
        Iterator iterator = xe.asStartElement().getAttributes(); // Use iterator since it tracks state
        while (iterator.hasNext()) {
            Attribute a = (Attribute) iterator.next();
            String v = a.getValue();
            switch (a.getName().getLocalPart()) {
                case XMLConstants.SERIALIZATION_VERSION_TAG:
                    versionNumber = v;
                    break;
                case STORED_TOKEN:
                    storedToken = v;
                    break;
                case TOKEN_TYPE:
                    tokenType = v;
                    break;
                case EXPIRES_AT_ATTR:
                    expiresAt = Long.parseLong(v);
                    break;
                case ISSUED_AT_ATTR:
                    issuedAt = Long.parseLong(v);
                    break;
                case LIFETIME_ATTR:
                    lifetime = Long.parseLong(v);
                    break;
                case ID_ATTR:
                    setIdentifier(BasicIdentifier.newID(v));
                    break;
                case PARENT_ID:
                    setParentID(BasicIdentifier.newID(v));
                    break;
                case ISSUER:
                    issuer = v;
                    break;
                case IS_VALID_ATTR:
                    valid = Boolean.parseBoolean(v);
                    break;
            }
        }
        return versionNumber;
    }

}
