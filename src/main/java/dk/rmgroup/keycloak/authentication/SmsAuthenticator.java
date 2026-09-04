package dk.rmgroup.keycloak.authentication;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.Base64;
import java.util.Locale;
import java.util.Properties;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.json.JSONObject;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import dk.rmgroup.keycloak.KeycloakSmsConstants;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

public class SmsAuthenticator implements Authenticator {
  private static final Logger logger = Logger.getLogger(SmsAuthenticator.class);

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    // Implement SMS authentication logic here
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    KeycloakSession session = context.getSession();
    UserModel user = context.getUser();
    AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();

    String mobileNumber = user.getFirstAttribute(KeycloakSmsConstants.ATTR_MOBILE);
    EventBuilder event = context.getEvent();

    if (mobileNumber == null || mobileNumber.trim().isEmpty()) {
      event.user(user)
          .detail(Details.USERNAME, user.getUsername())
          .error(KeycloakSmsConstants.INVALID_MOBILE);

      Response challenge = context.form()
          .setError(KeycloakSmsConstants.MESSAGE_NO_MOBILE)
          .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);

      context.failure(AuthenticationFlowError.INVALID_USER, challenge);
      return;
    }

    String code = SecretGenerator.getInstance().randomString(6, SecretGenerator.DIGITS);
    int ttl = 300; // Time-to-live for the SMS code in seconds

    authenticationSession.setAuthNote("sms-2fa-code", code);
    authenticationSession.setAuthNote("sms-2fa-ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

    try {
      Theme theme = session.theme().getTheme(Theme.Type.EMAIL);
      Locale locale = session.getContext().resolveLocale(user);
      Properties messages = theme.getMessages(locale);
      String smsCodeMessage = new MessageFormat(messages.getProperty("sms2faCodeMessage"), locale)
          .format(new String[] { code });

      String provider = getConfigString(config, KeycloakSmsConstants.CONF_SMS_PROVIDER);
      switch (provider) {
        case KeycloakSmsConstants.CONF_SMS_PROVIDER_BLUEIDEA:
          sendBlueIdeaSms(context, smsCodeMessage, mobileNumber, user, user.getUsername());
          break;
        case KeycloakSmsConstants.CONF_SMS_PROVIDER_VONAGE:
          sendVonageSms(context, smsCodeMessage, mobileNumber, user, user.getUsername());
          break;
        default:
          event.clone().event(EventType.SEND_RESET_PASSWORD)
              .detail(Details.USERNAME, user.getUsername())
              .detail(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber)
              .user(user)
              .error(KeycloakSmsConstants.SMS_SEND_FAILED);
          logger.error("Failed to send sms, unknown provider: " + provider);
          Response challenge = context.form()
              .setError(KeycloakSmsConstants.MESSAGE_SMS_SEND_ERROR)
              .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
          context.failure(AuthenticationFlowError.INTERNAL_ERROR, challenge);
          break;
      }

      Response form = context.form().createForm("code-from-sms.ftl");

      context.challenge(form);
    } catch (Exception ex) {
      event.clone().event(EventType.SEND_RESET_PASSWORD)
          .detail(Details.USERNAME, user.getUsername())
          .detail(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber)
          .user(user)
          .error(KeycloakSmsConstants.SMS_SEND_FAILED);

      logger.error("Failed to send SMS", ex);

      Response challenge = context.form()
          .setError(KeycloakSmsConstants.MESSAGE_SMS_SEND_ERROR)
          .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
      context.failure(AuthenticationFlowError.INTERNAL_ERROR, challenge);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    if (!validateAnswer(context)) {
      Response challenge = context.form()
          .setError("badCode")
          .createForm("code-from-sms.ftl");
      context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
    } else {
      String ttl = context.getAuthenticationSession().getAuthNote("sms-2fa-ttl");
      if (Long.parseLong(ttl) < System.currentTimeMillis()) {
        context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
            context.form().setError(KeycloakSmsConstants.MESSAGE_SMS_CODE_EXPIRED)
                .createErrorPage(Response.Status.BAD_REQUEST));
      } else {
        context.success();
      }
    }
  }

  protected boolean validateAnswer(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    String secret = formData.getFirst("sms_code");
    String authNote = context.getAuthenticationSession().getAuthNote("sms-2fa-code");
    return authNote != null && authNote.equals(secret);
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    // Implement setting required actions here
  }

  @Override
  public void close() {
    // Implement any cleanup logic here
  }

  private static String getConfigString(AuthenticatorConfigModel config, String configName) {

    String value = "";

    if (config.getConfig() != null) {
      // Get value
      value = config.getConfig().get(configName);
    }

    return value;
  }

  private static void sendBlueIdeaSms(AuthenticationFlowContext context, String smsTextMessage, String mobileNumber,
      UserModel user, String username) {
    EventBuilder event = context.getEvent();

    try {
      AuthenticatorConfigModel config = context.getAuthenticatorConfig();

      AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();

      String blueIdeaToken = getBlueIdeaToken(context);

      URL url = URI.create("https://api.sms-service.dk/Message/SendSingle").toURL();

      HttpURLConnection connection = (HttpURLConnection) url.openConnection();
      connection.setRequestMethod("POST");
      connection.setRequestProperty("Content-Type", "application/json");
      connection.setRequestProperty("Accept", "application/json");
      connection.setRequestProperty("Authorization", "Bearer " + blueIdeaToken);
      connection.setDoOutput(true);
      try (OutputStream os = connection.getOutputStream();
          OutputStreamWriter osw = new OutputStreamWriter(os, StandardCharsets.UTF_8)) {

        String inputText = "{\"messageText\":\"" + smsTextMessage.replace("\n", "\\n") + "\", \"phone\":\""
            + mobileNumber + "\", \"smsSendAs\":\""
            + getConfigString(config, KeycloakSmsConstants.CONF_SMS_FROM)
            + "\", \"profileId\":\""
            + getConfigString(config, KeycloakSmsConstants.CONF_SMS_BLUEIDEA_PROFILE_ID)
            + "\", \"sendInstantly\":true}";

        osw.write(inputText);
        osw.flush();
      }
      connection.connect();

      String responseString;

      try (InputStream responseStream = connection.getInputStream()) {
        responseString = new BufferedReader(
            new InputStreamReader(responseStream, StandardCharsets.UTF_8))
            .lines()
            .collect(Collectors.joining("\n"));
      } catch (Exception e) {
        logger.error("Failed to get response string", e);
        responseString = "Failed to get response string";
      }

      int statusCode = connection.getResponseCode();

      if (statusCode == 200) {
        event.clone().event(EventType.LOGIN)
            .user(user)
            .detail(Details.USERNAME, username)
            .detail(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber)
            .detail("status_code", String.valueOf(statusCode))
            .detail("response", responseString)
            .detail(Details.CODE_ID, authenticationSession.getParentSession().getId()).success();
      } else {
        event.clone().event(EventType.LOGIN_ERROR)
            .detail(Details.USERNAME, username)
            .detail(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber)
            .user(user)
            .detail("status_code", String.valueOf(statusCode))
            .detail("response", responseString)
            .error(KeycloakSmsConstants.SMS_SEND_FAILED);

        Response challenge = context.form()
            .setError(KeycloakSmsConstants.MESSAGE_SMS_SEND_ERROR)
            .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
        context.failure(AuthenticationFlowError.INTERNAL_ERROR, challenge);
      }

    } catch (Exception ex) {
      event.clone().event(EventType.LOGIN_ERROR)
          .detail(Details.USERNAME, username)
          .detail(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber)
          .user(user)
          .error(KeycloakSmsConstants.SMS_SEND_FAILED);

      logger.error("Failed to send sms", ex);

      Response challenge = context.form()
          .setError(KeycloakSmsConstants.MESSAGE_SMS_SEND_ERROR)
          .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
      context.failure(AuthenticationFlowError.INTERNAL_ERROR, challenge);
    }
  }

  private static String getBlueIdeaToken(AuthenticationFlowContext context) throws Exception {
    try {
      AuthenticatorConfigModel config = context.getAuthenticatorConfig();

      URL url = URI.create("https://api.sms-service.dk/User/Login").toURL();

      HttpURLConnection connection = (HttpURLConnection) url.openConnection();
      connection.setRequestMethod("POST");
      connection.setRequestProperty("Content-Type", "application/json");
      connection.setRequestProperty("Accept", "application/json");
      connection.setDoOutput(true);
      try (OutputStream os = connection.getOutputStream();
          OutputStreamWriter osw = new OutputStreamWriter(os, StandardCharsets.UTF_8)) {

        String inputText = "{\"email\":\""
            + getConfigString(config, KeycloakSmsConstants.CONF_SMS_BLUEIDEA_EMAIL)
            + "\", \"password\":\""
            + getConfigString(config, KeycloakSmsConstants.CONF_SMS_BLUEIDEA_PASSWORD) + "\"}";

        osw.write(inputText);
        osw.flush();
      }
      connection.connect();

      String responseString;

      try (InputStream responseStream = connection.getInputStream()) {
        responseString = new BufferedReader(
            new InputStreamReader(responseStream, StandardCharsets.UTF_8))
            .lines()
            .collect(Collectors.joining("\n"));
      } catch (Exception e) {
        logger.error("Failed to get response string", e);
        responseString = "Failed to get response string";
      }

      int statusCode = connection.getResponseCode();

      if (statusCode == 200) {
        JSONObject obj = new JSONObject(responseString);
        String accessToken = obj.getString("accessToken");
        return accessToken;
      } else {
        throw new Exception(
            "Failed to get blueIdea token, status code: " + statusCode + ", response: " + responseString);
      }

    } catch (Exception ex) {
      throw new Exception("Failed to get blueIdea token", ex);
    }
  }

  private void sendVonageSms(AuthenticationFlowContext context, String smsTextMessage, String mobileNumber,
      UserModel user, String username) {
    EventBuilder event = context.getEvent();

    try {
      AuthenticatorConfigModel config = context.getAuthenticatorConfig();

      AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();

      URL url = URI.create("https://api-eu.nexmo.com/v1/messages").toURL();

      HttpURLConnection connection = (HttpURLConnection) url.openConnection();
      connection.setRequestMethod("POST");
      connection.setRequestProperty("Content-Type", "application/json");
      connection.setRequestProperty("Accept", "application/json");
      String base64EncodedApiKey = Base64.getEncoder()
          .encodeToString((getConfigString(config, KeycloakSmsConstants.CONF_SMS_API_KEY) + ":"
              + getConfigString(config, KeycloakSmsConstants.CONF_SMS_API_SECRET)).getBytes(StandardCharsets.UTF_8));
      connection.setRequestProperty("Authorization", "Basic " + base64EncodedApiKey);
      connection.setDoOutput(true);
      try (OutputStream os = connection.getOutputStream();
          OutputStreamWriter osw = new OutputStreamWriter(os, StandardCharsets.UTF_8)) {

        String inputText = "{\"from\": \"" + getConfigString(config, KeycloakSmsConstants.CONF_SMS_FROM)
            + "\", \"to\": \"" + mobileNumber + "\", \"text\": \"" + smsTextMessage.replace("\n", "\\n")
            + "\", \"message_type\": \"text\", \"channel\": \"sms\"}";

        osw.write(inputText);
        osw.flush();
      }
      connection.connect();

      String responseString;

      try (InputStream responseStream = connection.getInputStream()) {
        responseString = new BufferedReader(
            new InputStreamReader(responseStream, StandardCharsets.UTF_8))
            .lines()
            .collect(Collectors.joining("\n"));
      } catch (Exception e) {
        logger.error("Failed to get response string", e);
        responseString = "Failed to get response string";
      }

      int statusCode = connection.getResponseCode();

      if (statusCode == 202) {
        event.clone().event(EventType.LOGIN)
            .user(user)
            .detail(Details.USERNAME, username)
            .detail(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber)
            .detail("status_code", String.valueOf(statusCode))
            .detail("response", responseString)
            .detail(Details.CODE_ID, authenticationSession.getParentSession().getId()).success();
      } else {
        event.clone().event(EventType.LOGIN_ERROR)
            .detail(Details.USERNAME, username)
            .detail(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber)
            .user(user)
            .detail("status_code", String.valueOf(statusCode))
            .detail("response", responseString)
            .error(KeycloakSmsConstants.SMS_SEND_FAILED);

        Response challenge = context.form()
            .setError(KeycloakSmsConstants.MESSAGE_SMS_SEND_ERROR)
            .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
        context.failure(AuthenticationFlowError.INTERNAL_ERROR, challenge);
      }
    } catch (IOException e) {
      event.clone().event(EventType.LOGIN_ERROR)
          .detail(Details.USERNAME, username)
          .detail(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber)
          .user(user)
          .error(KeycloakSmsConstants.SMS_SEND_FAILED);

      logger.error("Failed to send sms", e);

      Response challenge = context.form()
          .setError(KeycloakSmsConstants.MESSAGE_SMS_SEND_ERROR)
          .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
      context.failure(AuthenticationFlowError.INTERNAL_ERROR, challenge);
    }
  }

}
