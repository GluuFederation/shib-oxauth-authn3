package org.gluu.idp.context;

import java.util.List;

import org.opensaml.messaging.context.BaseContext;

import net.shibboleth.idp.attribute.IdPAttribute;

public final class GluuScratchContext extends BaseContext{
    
    private List<IdPAttribute> idpAttributes;


    public List<IdPAttribute> getIdpAttributes() {

        return this.idpAttributes;
    }

    public void setIdpAttributes(List<IdPAttribute> idpAttributes) {

        this.idpAttributes = idpAttributes;
    }
}
