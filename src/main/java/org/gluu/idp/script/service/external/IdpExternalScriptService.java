package org.gluu.idp.script.service.external;

import java.util.Map;

import org.gluu.model.SimpleCustomProperty;
import org.gluu.model.custom.script.CustomScriptType;
import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.model.custom.script.type.idp.IdpType;
import org.gluu.service.custom.script.ExternalScriptService;

/**
 * External IDP script service
 *
 * @author Yuriy Movchan
 * @version 0.1, 06/18/2020
 */
public class IdpExternalScriptService extends ExternalScriptService {

    private static final long serialVersionUID = -1316361273036208685L;

    public IdpExternalScriptService() {
        super(CustomScriptType.IDP);
    }

//  boolean translateAttributes(Object context, Map<String, SimpleCustomProperty> configurationAttributes);

  public boolean executeExternalTranslateAttributesMethod(Object context, CustomScriptConfiguration customScriptConfiguration) {
      try {
          log.debug("Executing python 'translateAttributes' method");
          IdpType idpType = (IdpType) customScriptConfiguration.getExternalType();
          Map<String, SimpleCustomProperty> configurationAttributes = customScriptConfiguration.getConfigurationAttributes();
          return idpType.translateAttributes(context, configurationAttributes);
      } catch (Exception ex) {
          log.error(ex.getMessage(), ex);
          saveScriptError(customScriptConfiguration.getCustomScript(), ex);
      }

      return false;
  }

  public boolean executeExternalTranslateAttributesMethod(Object context) {
      boolean result = true;
      for (CustomScriptConfiguration customScriptConfiguration : this.customScriptConfigurations) {
          if (customScriptConfiguration.getExternalType().getApiVersion() > 1) {
              result &= executeExternalTranslateAttributesMethod(context, customScriptConfiguration);
              if (!result) {
                  return result;
              }
          }
      }

      return result;
  }

//    boolean updateAttributes(Object context, Map<String, SimpleCustomProperty> configurationAttributes);

    public boolean executeExternalUpdateAttributesMethod(Object context, CustomScriptConfiguration customScriptConfiguration) {
        try {
            log.debug("Executing python 'updateAttributes' method");
            IdpType idpType = (IdpType) customScriptConfiguration.getExternalType();
            Map<String, SimpleCustomProperty> configurationAttributes = customScriptConfiguration.getConfigurationAttributes();
            return idpType.updateAttributes(context, configurationAttributes);
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(customScriptConfiguration.getCustomScript(), ex);
        }

        return false;
    }

    public boolean executeExternalUpdateAttributesMethod(Object context) {
        boolean result = true;
        for (CustomScriptConfiguration customScriptConfiguration : this.customScriptConfigurations) {
            if (customScriptConfiguration.getExternalType().getApiVersion() > 1) {
                result &= executeExternalUpdateAttributesMethod(context, customScriptConfiguration);
                if (!result) {
                    return result;
                }
            }
        }

        return result;
    }

    public boolean executeExternalPostAuthenticationMethod(Object context, CustomScriptConfiguration customScriptConfiguration) {
        try {
            log.debug("Executing python 'postAuthentication' method");
            IdpType idpType = (IdpType) customScriptConfiguration.getExternalType();
            Map<String, SimpleCustomProperty> configurationAttributes = customScriptConfiguration.getConfigurationAttributes();
            return idpType.postAuthentication(context, configurationAttributes);
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(customScriptConfiguration.getCustomScript(), ex);
        }

        return false;
    }

    public boolean executePostAuthenticationMethod(Object context) {
        boolean result = true;
        for (CustomScriptConfiguration customScriptConfiguration : this.customScriptConfigurations) {
            if (customScriptConfiguration.getExternalType().getApiVersion() > 12) {
                result &= executeExternalPostAuthenticationMethod(context, customScriptConfiguration);
                if (!result) {
                    return result;
                }
            }
        }

        return result;
    }

}
