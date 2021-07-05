package org.gluu.idp.context;

import java.util.List;

import org.opensaml.messaging.context.BaseContext;

import net.shibboleth.idp.attribute.IdPAttribute;

/**
 * Scratch context to pass data between the servlet and Shibboleth IDP
 * Currently being used only by the post-processing script, but could 
 * be used in other places
 * @author Djeumen Rolain
 * @version 0.1, 07/05/2021
 */
public final class GluuScratchContext extends BaseContext{
    
    private List<IdPAttribute> idpAttributes;


    public List<IdPAttribute> getIdpAttributes() {

        return this.idpAttributes;
    }

    public void setIdpAttributes(List<IdPAttribute> idpAttributes) {

        this.idpAttributes = idpAttributes;
    }
}
