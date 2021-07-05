package org.gluu.idp.externalauth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.gluu.oxauth.client.auth.user.UserProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;

/**
 * Simple translation of the principal name from the oxAuth user profile to the string value used by Shib
 *
 * @author Yuriy Movchan
 * @version 0.1, 09/13/2018
 */
public class AuthenticatedNameTranslator implements OxAuthToShibTranslator {
    private final Logger logger = LoggerFactory.getLogger(AuthenticatedNameTranslator.class);

    @Override
    public void doTranslation(HttpServletRequest request, HttpServletResponse response, UserProfile userProfile, String authenticationKey,
                              List<IdPAttribute> idpAttributes) throws Exception {
        
        if ((userProfile == null) || (userProfile.getId() == null)) {
            logger.error("No valid user profile or principal could be found to translate");
            return;
        }

        logger.debug("User profile found: '{}'", userProfile);

        populateIdpAttributeList(userProfile.getAttributes(), idpAttributes);
        
    }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

    @Override
    public boolean equals(final Object that) {
        return EqualsBuilder.reflectionEquals(this, that);
    }

    

    public void populateIdpAttributeList(final Map<String,Object> openidAttributes, final List<IdPAttribute> idpAttributes) {

        for(final Map.Entry<String, Object> entry: openidAttributes.entrySet()) {

            final IdPAttribute attr = new IdPAttribute(entry.getKey());

            final List<IdPAttributeValue> attributeValues = new ArrayList<IdPAttributeValue>();
            if(entry.getValue() instanceof Collection) {
                for (final Object value: (Collection) entry.getValue()) {
                    attributeValues.add(new StringAttributeValue(value.toString()));
                }
            }else {
                attributeValues.add(new StringAttributeValue(entry.getValue().toString()));
            }

            if(!attributeValues.isEmpty()) {
                attr.setValues(attributeValues);
                idpAttributes.add(attr);
                logger.debug("Added attribute {} with values {}", entry.getKey(), entry.getValue());
            }
        }
    }

}
