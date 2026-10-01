package org.wso2.support.sample.jwttokenissuer;

import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.support.sample.jwttokenissuer.MockedIdentityServer.OTHER_TENANT;
import static org.wso2.support.sample.jwttokenissuer.MockedIdentityServer.RS256;
import static org.wso2.support.sample.jwttokenissuer.MockedIdentityServer.TENANT;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;

/**
 * Runs the interceptor with the real issuer, JWTTokenIssuer and OAuth DTOs, against the mocked
 * Identity Server infrastructure, in the order Identity Server calls it.
 */
public class JWTRefreshTokenInterceptorTest {

  static final String JWT_APP = "jwt-app";
  static final String OTHER_APP = "default-app";
  static final long ISSUED_AT = 1790800000000L;
  static final long VALIDITY = 86400000L;

  private final JWTRefreshTokenInterceptor interceptor = new JWTRefreshTokenInterceptor();

  @Test
  public void replacesTheRefreshTokenOfApplicationsUsingTheIssuer() throws Exception {
    try (Fixture f = new Fixture(RS256, true)) {
      final String stored = UUID.randomUUID().toString();
      final OAuth2AccessTokenRespDTO response = f.issue(JWT_APP, stored);

      assertFalse(response.isError());
      final JWTClaimsSet claims = SignedJWT.parse(response.getRefreshToken()).getJWTClaimsSet();
      assertEquals(claims.getJWTID(), stored);
      assertEquals(claims.getIssueTime(), new Date(ISSUED_AT));
      assertEquals(claims.getExpirationTime(), new Date(ISSUED_AT + VALIDITY));
      assertEquals(claims.getSubject(), "subject-1");
      assertEquals(claims.getStringClaim("scope"), "email openid");
      assertEquals(claims.getStringClaim("aut"), "APPLICATION_USER");
      assertEquals(claims.getStringClaim("client_id"), JWT_APP);
    }
  }

  @Test
  public void replacesTheRefreshTokenOnRenewal() throws Exception {
    try (Fixture f = new Fixture(RS256, true)) {
      final String stored = UUID.randomUUID().toString();
      final OAuth2AccessTokenReqDTO request = request(JWT_APP, "presented", true);
      final OAuth2AccessTokenRespDTO response = response(stored);
      interceptor.onPostTokenRenewal(request, response, context(request, TENANT), new HashMap<>());
      assertEquals(SignedJWT.parse(response.getRefreshToken()).getJWTClaimsSet().getJWTID(), stored);
    }
  }

  @Test
  public void leavesOtherApplicationsUnchanged() throws Exception {
    try (Fixture f = new Fixture(RS256, true)) {
      assertEquals(f.issue(OTHER_APP, "opaque-1").getRefreshToken(), "opaque-1");
    }
  }

  @Test
  public void leavesResponsesWithoutARefreshTokenUnchanged() throws Exception {
    try (Fixture f = new Fixture(RS256, true)) {
      final OAuth2AccessTokenReqDTO request = request(JWT_APP, null, true);
      final OAuthTokenReqMessageContext context = context(request, TENANT);

      final OAuth2AccessTokenRespDTO error = response("stored-1");
      error.setError(true);
      interceptor.onPostTokenIssue(request, error, context, new HashMap<>());
      assertEquals(error.getRefreshToken(), "stored-1");

      final OAuth2AccessTokenRespDTO empty = response("");
      interceptor.onPostTokenIssue(request, empty, context, new HashMap<>());
      assertEquals(empty.getRefreshToken(), "");

      final OAuth2AccessTokenRespDTO none = response(null);
      interceptor.onPostTokenIssue(request, none, context, new HashMap<>());
      assertNull(none.getRefreshToken());

      // Identity Server passes a null response when the grant handler throws.
      interceptor.onPostTokenIssue(request, null, context, new HashMap<>());
    }
  }

  @Test
  public void doesNotWrapARefreshTokenTwice() throws Exception {
    try (Fixture f = new Fixture(RS256, true)) {
      final String jwt = f.issue(JWT_APP, "stored-1").getRefreshToken();
      final OAuth2AccessTokenReqDTO request = request(JWT_APP, null, true);
      final OAuth2AccessTokenRespDTO again = response(jwt);
      interceptor.onPostTokenIssue(request, again, context(request, TENANT), new HashMap<>());
      assertEquals(again.getRefreshToken(), jwt);
    }
  }

  @Test
  public void failsTheResponseWhenTheIssueTimeIsMissing() throws Exception {
    try (Fixture f = new Fixture(RS256, true)) {
      final OAuth2AccessTokenReqDTO request = request(JWT_APP, null, true);
      final OAuthTokenReqMessageContext context = context(request, TENANT);
      context.setRefreshTokenIssuedTime(0L);
      final OAuth2AccessTokenRespDTO response = response("stored-1");
      interceptor.onPostTokenIssue(request, response, context, new HashMap<>());
      assertServerError(response);
    }
  }

  @Test
  public void failsTheResponseWhenSigningFails() throws Exception {
    try (Fixture f = new Fixture(RS256, true)) {
      f.server.failPrivateKeyLookups();
      assertServerError(f.issue(JWT_APP, "stored-1"));
    }
  }

  @Test
  public void failsTheResponseWhenTheAlgorithmCannotBeUsed() throws Exception {
    try (Fixture f = new Fixture("SHA256withEC", true)) {
      assertServerError(f.issue(JWT_APP, "stored-1"));
    }
  }

  @Test
  public void leavesTheResponseUnchangedWhenTheIssuerCannotBeResolved() throws Exception {
    try (Fixture f = new Fixture(RS256, true)) {
      f.server.failAppLookups();
      final OAuth2AccessTokenRespDTO response = f.issue(JWT_APP, "stored-1");
      assertFalse(response.isError());
      assertEquals(response.getRefreshToken(), "stored-1");
    }
  }

  @Test
  public void turnsAJWTBackIntoTheStoredValueOnTheRefreshGrant() throws Exception {
    try (Fixture f = new Fixture(RS256, true)) {
      final String jwt = f.issue(JWT_APP, "stored-1").getRefreshToken();
      final OAuth2AccessTokenReqDTO request = request(JWT_APP, jwt, true);
      interceptor.onPreTokenRenewal(request, new OAuthTokenReqMessageContext(request), new HashMap<>());
      assertEquals(request.getRefreshToken(), "stored-1");
    }
  }

  @Test
  public void leavesOtherValuesUnchangedOnTheRefreshGrant() throws Exception {
    try (Fixture f = new Fixture(RS256, true)) {
      final String jwt = f.issue(JWT_APP, "stored-1").getRefreshToken();
      final String[] parts = jwt.split("\\.");
      final String tampered =
          parts[0] + "." + parts[1].substring(0, parts[1].length() - 2) + "AA." + parts[2];
      for (final String value :
          new String[] {"stored-1", "opaque-1", tampered, "a.b.c", "", null}) {
        final OAuth2AccessTokenReqDTO request = request(JWT_APP, value, true);
        interceptor.onPreTokenRenewal(
            request, new OAuthTokenReqMessageContext(request), new HashMap<>());
        assertEquals(request.getRefreshToken(), value);
      }
    }
  }

  @Test
  public void turnsAJWTBackIntoTheStoredValueOnRevocation() throws Exception {
    try (Fixture f = new Fixture(RS256, true)) {
      final String jwt = f.issue(JWT_APP, "stored-1").getRefreshToken();
      final OAuthRevocationRequestDTO revocation = new OAuthRevocationRequestDTO();
      revocation.setConsumerKey(JWT_APP);
      revocation.setToken(jwt);
      interceptor.onPreTokenRevocationByClient(revocation, new HashMap<>());
      assertEquals(revocation.getToken(), "stored-1");

      revocation.setToken("opaque-1");
      interceptor.onPreTokenRevocationByClient(revocation, new HashMap<>());
      assertEquals(revocation.getToken(), "opaque-1");
    }
  }

  @Test
  public void turnsAJWTBackIntoTheStoredValueOnIntrospection() throws Exception {
    try (Fixture f = new Fixture(RS256, true)) {
      final String jwt = f.issue(JWT_APP, "stored-1").getRefreshToken();
      final OAuth2TokenValidationRequestDTO validation = new OAuth2TokenValidationRequestDTO();
      final OAuth2TokenValidationRequestDTO.OAuth2AccessToken token =
          validation.new OAuth2AccessToken();
      token.setIdentifier(jwt);
      validation.setAccessToken(token);
      interceptor.onPreTokenValidation(validation, new HashMap<>());
      assertEquals(token.getIdentifier(), "stored-1");

      token.setIdentifier("opaque-1");
      interceptor.onPreTokenValidation(validation, new HashMap<>());
      assertEquals(token.getIdentifier(), "opaque-1");

      // No token in the request.
      interceptor.onPreTokenValidation(new OAuth2TokenValidationRequestDTO(), new HashMap<>());
    }
  }

  @Test
  public void acceptsRefreshTokensOfApplicationsThatNoLongerUseTheIssuer() throws Exception {
    try (Fixture f = new Fixture(RS256, true)) {
      final String jwt = f.issue(JWT_APP, "stored-1").getRefreshToken();
      // The application moves to another token type; its clients still hold JWTs.
      f.server.addApp(JWT_APP, TENANT, mock(OauthTokenIssuer.class));
      final OAuth2AccessTokenReqDTO request = request(JWT_APP, jwt, true);
      interceptor.onPreTokenRenewal(request, new OAuthTokenReqMessageContext(request), new HashMap<>());
      assertEquals(request.getRefreshToken(), "stored-1");
      // New refresh tokens are no longer wrapped.
      assertEquals(f.issue(JWT_APP, "stored-2").getRefreshToken(), "stored-2");
    }
  }

  @DataProvider
  public Object[][] configurations() {
    return new Object[][] {
      {"SHA256withRSA", true}, {"SHA384withRSA", true}, {"SHA512withRSA", true}, {"PS256", true},
      {"NONE", true}, {"SHA256withRSA", false}, {"PS256", false},
    };
  }

  @Test(dataProvider = "configurations")
  public void roundTripsThroughEveryHook(final String algorithm, final boolean signWithAppTenant)
      throws Exception {
    try (Fixture f = new Fixture(algorithm, signWithAppTenant)) {
      final String stored = UUID.randomUUID().toString();
      // A user of another tenant, as with a shared application.
      final String jwt = f.issue(JWT_APP, stored, OTHER_TENANT).getRefreshToken();
      assertTrue(JWTAccessRefreshTokenIssuer.isJWT(jwt));
      assertEquals(
          JWTParser.parse(jwt).getHeader().getAlgorithm().getName(),
          "NONE".equals(algorithm) ? "none" : f.expectedAlgorithm());

      final OAuth2AccessTokenReqDTO request = request(JWT_APP, jwt, true);
      interceptor.onPreTokenRenewal(request, new OAuthTokenReqMessageContext(request), new HashMap<>());
      assertEquals(request.getRefreshToken(), stored);
    }
  }

  static void assertServerError(final OAuth2AccessTokenRespDTO response) {
    assertTrue(response.isError());
    assertEquals(response.getErrorCode(), "server_error");
    assertNull(response.getRefreshToken(), "The stored value must not reach the client.");
  }

  static OAuth2AccessTokenReqDTO request(
      final String clientId, final String refreshToken, final boolean authenticated) {
    final OAuth2AccessTokenReqDTO request = new OAuth2AccessTokenReqDTO();
    request.setClientId(clientId);
    request.setGrantType("refresh_token");
    request.setRefreshToken(refreshToken);
    final OAuthClientAuthnContext authn = new OAuthClientAuthnContext();
    authn.setClientId(clientId);
    authn.setAuthenticated(authenticated);
    request.setoAuthClientAuthnContext(authn);
    return request;
  }

  static OAuthTokenReqMessageContext context(
      final OAuth2AccessTokenReqDTO request, final String userTenant) {
    final OAuthTokenReqMessageContext context = new OAuthTokenReqMessageContext(request);
    final AuthenticatedUser user = JWTAccessRefreshTokenIssuerTest.user(userTenant);
    context.setAuthorizedUser(user);
    context.setScope(new String[] {"openid", "email"});
    context.setRefreshTokenIssuedTime(ISSUED_AT);
    context.setRefreshTokenvalidityPeriod(VALIDITY);
    context.addProperty(OAuthConstants.UserType.USER_TYPE, OAuthConstants.UserType.APPLICATION_USER);
    return context;
  }

  static OAuth2AccessTokenRespDTO response(final String refreshToken) {
    final OAuth2AccessTokenRespDTO response = new OAuth2AccessTokenRespDTO();
    response.setAccessToken("access-token");
    response.setRefreshToken(refreshToken);
    return response;
  }

  /** A mocked server with one application on the issuer and one on another token type. */
  final class Fixture implements AutoCloseable {
    final MockedIdentityServer server;
    private final String algorithm;

    Fixture(final String algorithm, final boolean signWithAppTenant) throws Exception {
      this.algorithm = algorithm;
      server = new MockedIdentityServer(algorithm, signWithAppTenant);
      server.addApp(JWT_APP, TENANT, new JWTAccessRefreshTokenIssuer());
      server.addApp(OTHER_APP, TENANT, mock(OauthTokenIssuer.class));
    }

    OAuth2AccessTokenRespDTO issue(final String clientId, final String stored) {
      return issue(clientId, stored, TENANT);
    }

    OAuth2AccessTokenRespDTO issue(
        final String clientId, final String stored, final String userTenant) {
      final OAuth2AccessTokenReqDTO request = request(clientId, null, true);
      request.setGrantType("authorization_code");
      final OAuth2AccessTokenRespDTO response = response(stored);
      interceptor.onPostTokenIssue(request, response, context(request, userTenant), new HashMap<>());
      return response;
    }

    String expectedAlgorithm() {
      return Collections.singletonMap("SHA256withRSA", "RS256").getOrDefault(algorithm,
          algorithm.startsWith("SHA384") ? "RS384" : algorithm.startsWith("SHA512") ? "RS512" : algorithm);
    }

    @Override
    public void close() {
      server.close();
    }
  }
}
