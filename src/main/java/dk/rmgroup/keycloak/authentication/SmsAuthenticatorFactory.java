package dk.rmgroup.keycloak.authentication;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import dk.rmgroup.keycloak.KeycloakSmsConstants;

public class SmsAuthenticatorFactory implements AuthenticatorFactory {
  public static final String PROVIDER_ID = "sms-2fa";
  private static final Authenticator SINGLETON = new SmsAuthenticator();

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
      AuthenticationExecutionModel.Requirement.REQUIRED,
      AuthenticationExecutionModel.Requirement.ALTERNATIVE,
      AuthenticationExecutionModel.Requirement.DISABLED
  };

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return true;
  }

  private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

  static {
    ProviderConfigProperty property;
    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_PROVIDER);
    property.setLabel("Provider");
    property.setType(ProviderConfigProperty.LIST_TYPE);
    property.setHelpText("The sms provider to use");
    property.setRequired(true);
    property.setOptions(new ArrayList<String>() {
      {
        add(KeycloakSmsConstants.CONF_SMS_PROVIDER_VONAGE);
        add(KeycloakSmsConstants.CONF_SMS_PROVIDER_BLUEIDEA);
      }
    });
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_API_KEY);
    property.setLabel("Vonage Api Key");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The api key for vonage. (Only used if provider is Vonage)");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_API_SECRET);
    property.setLabel("Vonage Api Secret");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The api secret for vonage. (Only used if provider is Vonage)");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_FROM);
    property.setLabel("Sender");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The name of the sender. Is what is show as the sender in the sms.");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_BLUEIDEA_EMAIL);
    property.setLabel("Blueidea Email");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The email for blueidea. (Only used if provider is Blueidea)");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_BLUEIDEA_PASSWORD);
    property.setLabel("Blueidea password");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The password for blueidea. (Only used if provider is Blueidea)");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_BLUEIDEA_PROFILE_ID);
    property.setLabel("Blueidea profile id");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The profile id for blueidea. (Only used if provider is Blueidea)");
    configProperties.add(property);

  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return configProperties;
  }

  @Override
  public String getHelpText() {
    return "Validates an OTP sent via SMS to the users mobile phone.";
  }

  @Override
  public String getDisplayType() {
    return "SMS 2FA";
  }

  @Override
  public String getReferenceCategory() {
    return "mobile-number";
  }

  @Override
  public void init(Config.Scope config) {
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
  }

  @Override
  public void close() {
  }
}