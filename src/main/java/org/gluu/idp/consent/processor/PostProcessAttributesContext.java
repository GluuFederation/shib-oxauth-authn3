package org.gluu.idp.consent.processor;

import java.io.Serializable;

import net.shibboleth.idp.attribute.context.AttributeContext;

/**
 * Post process attributes context
 *
 * @author Yuriy Movchan
 * @version 0.1, 06/22/2020
 */
public class PostProcessAttributesContext implements Serializable {

	private static final long serialVersionUID = 1822377169827670256L;

	private AttributeContext attributeContext;
	private GluuReleaseAttributesPostProcessor releaseAttributesPostProcessor;

	public void setAttributeContext(AttributeContext attributeContext) {
		this.attributeContext = attributeContext;
	}

	public AttributeContext getAttributeContext() {
		return attributeContext;
	}

	public void setAttributeReleaseAction(GluuReleaseAttributesPostProcessor releaseAttributesPostProcessor) {
		this.releaseAttributesPostProcessor = releaseAttributesPostProcessor;
	}

	public GluuReleaseAttributesPostProcessor getGluuReleaseAttributesPostProcessor() {
		return releaseAttributesPostProcessor;
	}

	public void setGluuReleaseAttributesPostProcessor(GluuReleaseAttributesPostProcessor releaseAttributesPostProcessor) {
		this.releaseAttributesPostProcessor = releaseAttributesPostProcessor;
	}

}
