package org.wso2.carbon.identity.saml.inbound;

import java.util.HashMap;
import java.util.Map;

public class SAMLConfigurations {

    private static Map configuration = new HashMap<>();

    static {
         configuration.put("KeyStore.Location",
                 "/media/hasinthaindrajee/204c7dcd-f122-4bc5-9743-f46bcdf78f37/530/wso2is-5.3" +
                         ".0/repository/resources/security/wso2carbon.jks");
        configuration.put("KeyStore.Type", "JKS");
        configuration.put("KeyStore.Password", "wso2carbon");
        configuration.put("KeyStore.KeyAlias", "wso2carbon");
        configuration.put("SAMLResponseValidityPeriod", 5);
    }

    public static String getProperty(String propertyName) {
       return (String) configuration.get(propertyName);
    }
}
