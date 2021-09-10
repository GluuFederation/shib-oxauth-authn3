package org.gluu.idp.externalauth;

import javax.annotation.Nonnull;

import org.gluu.util.StringHelper;
import org.opensaml.profile.context.ProfileRequestContext;

import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.impl.ValidateExternalAuthentication;

public class OxAuthValidateExternalAuthentication extends ValidateExternalAuthentication {

	/** {@inheritDoc} */
	@Override
	protected void buildAuthenticationResult(@Nonnull final ProfileRequestContext profileRequestContext,
			@Nonnull final AuthenticationContext authenticationContext) {
		super.buildAuthenticationResult(profileRequestContext, authenticationContext);

		Object usedAcr = authenticationContext.getAuthenticationStateMap().get(ShibOxAuthAuthServlet.OXAUTH_ACR_USED);
		if (StringHelper.isNotEmptyString(usedAcr)) {
			final AuthenticationResult result = authenticationContext.getAuthenticationResult();
			result.getAdditionalData().put(ShibOxAuthAuthServlet.OXAUTH_ACR_USED, StringHelper.toString(usedAcr));
		}
	}

}