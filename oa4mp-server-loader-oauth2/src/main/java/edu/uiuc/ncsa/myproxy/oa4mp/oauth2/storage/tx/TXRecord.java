package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx;

import edu.uiuc.ncsa.qdl.xml.XMLUtils;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;
import edu.uiuc.ncsa.security.core.util.StringUtils;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.XMLEvent;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import static edu.uiuc.ncsa.myproxy.oa4mp.qdl.QDLXMLConstants.*;
import static edu.uiuc.ncsa.qdl.xml.XMLUtils.readStemAsStrings;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  8:54 AM
 */
public class TXRecord extends IdentifiableImpl {
    public TXRecord(Identifier identifier) {
        super(identifier);
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

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    /**
     * Convenience method. Just got tired of translating this
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

    public void toXML(XMLStreamWriter xsw) throws XMLStreamException{
         xsw.writeStartElement(TX_RECORD);
         xsw.writeAttribute(ID_ATTR, getIdentifierString());
         xsw.writeAttribute(EXPIRES_AT_ATTR, Long.toString(expiresAt));
         xsw.writeAttribute(LIFETIME_ATTR, Long.toString(lifetime));
         xsw.writeAttribute(ISSUED_AT_ATTR, Long.toString(issuedAt));
         xsw.writeAttribute(IS_VALID_ATTR, Boolean.toString(valid));
         if(!StringUtils.isTrivial(issuer)){
             xsw.writeAttribute(ISSUER, issuer);
         }
         if(!StringUtils.isTrivial(tokenType)) {
             xsw.writeAttribute(TOKEN_TYPE, tokenType);
         }
         if(getParentID()!=null){
             xsw.writeAttribute(PARENT_ID, getParentID().toString());
         }
         if(scopes != null && !scopes.isEmpty()){
             xsw.writeStartElement(SCOPES);
             XMLUtils.write(xsw, scopes);
             xsw.writeEndElement(); // close scopes
         }
         if(audience != null && !audience.isEmpty()){
             xsw.writeStartElement(AUDIENCE);
             XMLUtils.write(xsw, audience);
             xsw.writeEndElement(); // close audience
         }

        if(resource != null && !resource.isEmpty()){
            xsw.writeStartElement(RESOURCES);
            XMLUtils.write(xsw, resource);
            xsw.writeEndElement(); // close scopes
        }

         xsw.writeEndElement(); // close tag for TX record
    }
    public void fromXML(XMLEventReader xer) throws XMLStreamException{
        XMLEvent xe = xer.nextEvent();
        doXMLAttributes(xe);
        // process all the attributes
        while(xer.hasNext()){
            xe = xer.peek();

              switch (xe.getEventType()){
                  case XMLEvent.START_ELEMENT:
                      switch(xe.asStartElement().getName().getLocalPart()){
                          case AUDIENCE:
                              audience = readStemAsStrings(xer);
                              break;
                          case SCOPES:
                              scopes = readStemAsStrings(xer);
                              break;
                          case RESOURCES:
                              List<String> ll = readStemAsStrings(xer);
                              resource = new ArrayList<URI>();
                              for(String s : ll){
                                  resource.add(URI.create(s));
                              }
                              break;
                      }
                      break;
                  case XMLEvent.END_ELEMENT:
                      if(xe.asEndElement().getName().getLocalPart().equals(TX_RECORD)){
                          return;
                      }
                      break;
              }
            xer.next();
        }
        throw new IllegalStateException("Error: XML file corrupt. No end tag for " + TX_RECORD);

    }

    private void doXMLAttributes(XMLEvent xe) {
        Iterator iterator = xe.asStartElement().getAttributes(); // Use iterator since it tracks state
               while (iterator.hasNext()) {
                   Attribute a = (Attribute) iterator.next();
                   String v = a.getValue();
                   switch (a.getName().getLocalPart()) {
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

    }

}
