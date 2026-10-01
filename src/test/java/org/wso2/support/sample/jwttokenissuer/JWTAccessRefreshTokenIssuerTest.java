package org.wso2.support.sample.jwttokenissuer;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;
import static org.wso2.support.sample.jwttokenissuer.MockedIdentityServer.OTHER_TENANT;
import static org.wso2.support.sample.jwttokenissuer.MockedIdentityServer.RS256;
import static org.wso2.support.sample.jwttokenissuer.MockedIdentityServer.TENANT;
import static org.wso2.support.sample.jwttokenissuer.MockedIdentityServer.keyPair;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

public class JWTAccessRefreshTokenIssuerTest {

  private static final String CLIENT_ID = "jwt-app";
  private static final long ISSUED_AT = 1790800000000L;
  private static final long VALIDITY = 86400000L;

  // Parsing and helpers (no Identity Server infrastructure involved).

  @Test
  public void parsesSignedAndUnsignedRefreshTokens() throws Exception {
    assertNotNull(JWTAccessRefreshTokenIssuer.parseRefreshTokenJWT(signedWith("rt+jwt", "abc")));
    assertNotNull(JWTAccessRefreshTokenIssuer.parseRefreshTokenJWT(unsigned("rt+jwt", "abc")));
  }

  @Test
  public void ignoresOtherTokens() throws Exception {
    assertNull(JWTAccessRefreshTokenIssuer.parseRefreshTokenJWT(signedWith("at+jwt", "abc")));
    assertNull(JWTAccessRefreshTokenIssuer.parseRefreshTokenJWT(signedWith(null, "abc")));
    assertNull(JWTAccessRefreshTokenIssuer.parseRefreshTokenJWT(unsigned(null, "abc")));
    assertNull(
        JWTAccessRefreshTokenIssuer.parseRefreshTokenJWT("6f1c8a52-0e4e-3c1d-9a0e-3a2f1b9d8c77"));
    assertNull(JWTAccessRefreshTokenIssuer.parseRefreshTokenJWT("not.a.jwt"));
    assertNull(JWTAccessRefreshTokenIssuer.parseRefreshTokenJWT(""));
    assertNull(JWTAccessRefreshTokenIssuer.parseRefreshTokenJWT(null));
  }

  @Test
  public void opaqueValuesAreNotVerified() {
    assertNull(JWTAccessRefreshTokenIssuer.getVerifiedJwtId("6f1c8a52-0e4e-3c1d-9a0e-3a2f1b9d8c77"));
    assertNull(JWTAccessRefreshTokenIssuer.getVerifiedJwtId(null));
  }

  @Test
  public void recognisesJWTs() throws Exception {
    assertTrue(JWTAccessRefreshTokenIssuer.isJWT(signedWith("rt+jwt", "abc")));
    assertTrue(JWTAccessRefreshTokenIssuer.isJWT(unsigned("rt+jwt", "abc")));
    assertFalse(JWTAccessRefreshTokenIssuer.isJWT("6f1c8a52-0e4e-3c1d-9a0e-3a2f1b9d8c77"));
    assertFalse(JWTAccessRefreshTokenIssuer.isJWT(null));
  }

  @Test
  public void ordersScopesForTheScopeClaim() {
    assertEquals(
        JWTAccessRefreshTokenIssuer.scopeClaimValue(
            new String[] {"profile", "openid", "email", "openid"}),
        "email openid profile");
    assertNull(JWTAccessRefreshTokenIssuer.scopeClaimValue(new String[0]));
    assertNull(JWTAccessRefreshTokenIssuer.scopeClaimValue(null));
  }

  // Signing and verification against the mocked Identity Server.

  @DataProvider
  public Object[][] supportedAlgorithms() {
    return new Object[][] {
      {"SHA256withRSA", JWSAlgorithm.RS256},
      {"SHA384withRSA", JWSAlgorithm.RS384},
      {"SHA512withRSA", JWSAlgorithm.RS512},
      {"PS256", JWSAlgorithm.PS256},
    };
  }

  @Test(dataProvider = "supportedAlgorithms")
  public void signsWithTheConfiguredAlgorithm(final String configured, final JWSAlgorithm expected)
      throws Exception {
    try (MockedIdentityServer server = new MockedIdentityServer(configured, true)) {
      final JWTAccessRefreshTokenIssuer issuer = new JWTAccessRefreshTokenIssuer();
      server.addApp(CLIENT_ID, TENANT, issuer);
      final String jwtId = UUID.randomUUID().toString();

      final SignedJWT jwt = SignedJWT.parse(build(issuer, user(TENANT), jwtId, VALIDITY));

      assertEquals(jwt.getHeader().getAlgorithm(), expected);
      assertEquals(jwt.getHeader().getType().getType(), "rt+jwt");
      assertEquals(jwt.getHeader().getKeyID(), "kid-" + TENANT);
      assertEquals(jwt.getHeader().getX509CertThumbprint(), new Base64URL("thumbprint-" + TENANT));
      assertTrue(jwt.verify(new RSASSAVerifier((RSAPublicKey) keyPair(TENANT).getPublic())));
      assertEquals(JWTAccessRefreshTokenIssuer.getVerifiedJwtId(jwt.serialize()), jwtId);
    }
  }

  @Test
  public void setsTheRefreshTokenClaims() throws Exception {
    try (MockedIdentityServer server = new MockedIdentityServer(RS256, true)) {
      final JWTAccessRefreshTokenIssuer issuer = new JWTAccessRefreshTokenIssuer();
      server.addApp(CLIENT_ID, TENANT, issuer);

      final JWTClaimsSet claims =
          SignedJWT.parse(build(issuer, user(TENANT), "jti-1", VALIDITY)).getJWTClaimsSet();

      final String issuerUrl = MockedIdentityServer.issuerUrl(TENANT);
      assertEquals(claims.getIssuer(), issuerUrl);
      assertEquals(claims.getSubject(), "subject-1");
      assertEquals(claims.getAudience(), Collections.singletonList(issuerUrl));
      assertEquals(claims.getStringClaim("azp"), CLIENT_ID);
      assertEquals(claims.getStringClaim("client_id"), CLIENT_ID);
      assertEquals(claims.getIssueTime(), new Date(ISSUED_AT));
      assertEquals(claims.getNotBeforeTime(), new Date(ISSUED_AT));
      assertEquals(claims.getExpirationTime(), new Date(ISSUED_AT + VALIDITY));
      assertEquals(claims.getJWTID(), "jti-1");
      assertEquals(claims.getStringClaim("scope"), "email openid profile");
      assertNull(claims.getClaim("rt_scope"));
      assertEquals(claims.getStringClaim("aut"), "APPLICATION_USER");
      assertNull(claims.getClaim("realm"), "The realm claim is only added for user tenant signing.");
    }
  }

  @Test
  public void omitsTheExpiryForRefreshTokensThatDoNotExpire() throws Exception {
    try (MockedIdentityServer server = new MockedIdentityServer(RS256, true)) {
      final JWTAccessRefreshTokenIssuer issuer = new JWTAccessRefreshTokenIssuer();
      server.addApp(CLIENT_ID, TENANT, issuer);
      final JWTClaimsSet claims =
          SignedJWT.parse(build(issuer, user(TENANT), "jti-1", -1L)).getJWTClaimsSet();
      assertNull(claims.getExpirationTime());
    }
  }

  @Test
  public void usesTheClientIdAsSubjectWithoutAUser() throws Exception {
    try (MockedIdentityServer server = new MockedIdentityServer(RS256, true)) {
      final JWTAccessRefreshTokenIssuer issuer = new JWTAccessRefreshTokenIssuer();
      server.addApp(CLIENT_ID, TENANT, issuer);
      final String token =
          issuer.buildRefreshToken(CLIENT_ID, null, null, null, "jti-1", ISSUED_AT, VALIDITY);
      final JWTClaimsSet claims = SignedJWT.parse(token).getJWTClaimsSet();
      assertEquals(claims.getSubject(), CLIENT_ID);
      assertNull(claims.getClaim("scope"));
      assertNull(claims.getClaim("aut"));
    }
  }

  @Test
  public void issuesUnsignedRefreshTokensWhenTheServerIsConfiguredForNone() throws Exception {
    final String token;
    try (MockedIdentityServer server = new MockedIdentityServer("NONE", true)) {
      final JWTAccessRefreshTokenIssuer issuer = new JWTAccessRefreshTokenIssuer();
      server.addApp(CLIENT_ID, TENANT, issuer);
      token = build(issuer, user(TENANT), "jti-1", VALIDITY);

      final JWT jwt = JWTParser.parse(token);
      assertTrue(jwt instanceof PlainJWT);
      assertEquals(jwt.getHeader().getType().getType(), "rt+jwt");
      assertEquals(JWTAccessRefreshTokenIssuer.getVerifiedJwtId(token), "jti-1");
    }
    try (MockedIdentityServer server = new MockedIdentityServer(RS256, true)) {
      server.addApp(CLIENT_ID, TENANT, null);
      assertNull(
          JWTAccessRefreshTokenIssuer.getVerifiedJwtId(token),
          "Unsigned refresh tokens must be rejected once the server signs JWTs.");
    }
  }

  @DataProvider
  public Object[][] unsupportedAlgorithms() {
    return new Object[][] {
      {"SHA256withHMAC"}, {"SHA384withHMAC"}, {"SHA512withHMAC"},
      {"SHA256withEC"}, {"SHA384withEC"}, {"SHA512withEC"},
    };
  }

  @Test(dataProvider = "unsupportedAlgorithms")
  public void refusesAlgorithmsJWTTokenIssuerCannotSignWith(final String configured)
      throws Exception {
    try (MockedIdentityServer server = new MockedIdentityServer(configured, true)) {
      final JWTAccessRefreshTokenIssuer issuer = new JWTAccessRefreshTokenIssuer();
      server.addApp(CLIENT_ID, TENANT, issuer);
      final IdentityOAuth2Exception e =
          expectThrows(
              IdentityOAuth2Exception.class, () -> build(issuer, user(TENANT), "jti-1", VALIDITY));
      assertTrue(e.getMessage().contains("RSA signature algorithms only"), e.getMessage());
    }
  }

  @Test
  public void signsWithTheUserTenantKeyWhenConfigured() throws Exception {
    try (MockedIdentityServer server = new MockedIdentityServer(RS256, false)) {
      final JWTAccessRefreshTokenIssuer issuer = new JWTAccessRefreshTokenIssuer();
      // A shared application in the app tenant, used by a user of another tenant.
      server.addApp(CLIENT_ID, TENANT, issuer);

      final SignedJWT jwt =
          SignedJWT.parse(build(issuer, user(OTHER_TENANT), "jti-1", VALIDITY));

      final Map<String, Object> realm = jwt.getJWTClaimsSet().getJSONObjectClaim("realm");
      assertEquals(realm.get("signing_tenant"), OTHER_TENANT);
      assertEquals(jwt.getHeader().getKeyID(), "kid-" + OTHER_TENANT);
      assertTrue(jwt.verify(new RSASSAVerifier((RSAPublicKey) keyPair(OTHER_TENANT).getPublic())));
      assertFalse(jwt.verify(new RSASSAVerifier((RSAPublicKey) keyPair(TENANT).getPublic())));
      assertEquals(JWTAccessRefreshTokenIssuer.getVerifiedJwtId(jwt.serialize()), "jti-1");
    }
  }

  @Test
  public void ignoresTheRealmClaimWhenSigningWithTheAppTenantKey() throws Exception {
    try (MockedIdentityServer server = new MockedIdentityServer(RS256, true)) {
      server.addApp(CLIENT_ID, TENANT, null);
      // Signed with another tenant's key and claiming that tenant: must not be trusted.
      final String forged =
          signedWith(
              "rt+jwt",
              claims("jti-1", CLIENT_ID)
                  .claim(
                      "realm", Collections.singletonMap("signing_tenant", OTHER_TENANT))
                  .build(),
              OTHER_TENANT);
      assertNull(JWTAccessRefreshTokenIssuer.getVerifiedJwtId(forged));
    }
  }

  @Test
  public void rejectsRefreshTokensThatCannotBeVerified() throws Exception {
    try (MockedIdentityServer server = new MockedIdentityServer(RS256, true)) {
      final JWTAccessRefreshTokenIssuer issuer = new JWTAccessRefreshTokenIssuer();
      server.addApp(CLIENT_ID, TENANT, issuer);
      final String valid = build(issuer, user(TENANT), "jti-1", VALIDITY);
      final String[] parts = valid.split("\\.");
      final String other = build(issuer, user(TENANT), "jti-2", VALIDITY);

      // Payload changed, signature kept.
      final String tamperedPayload =
          parts[0]
              + "."
              + Base64URL.encode(
                  claims("jti-other", CLIENT_ID).build().toString())
              + "."
              + parts[2];
      assertNull(JWTAccessRefreshTokenIssuer.getVerifiedJwtId(tamperedPayload));
      // Signature taken from another token.
      assertNull(
          JWTAccessRefreshTokenIssuer.getVerifiedJwtId(
              parts[0] + "." + parts[1] + "." + other.split("\\.")[2]));
      // Signed with a key Identity Server does not hold.
      assertNull(
          JWTAccessRefreshTokenIssuer.getVerifiedJwtId(
              signedWith("rt+jwt", claims("jti-1", CLIENT_ID).build(), "attacker")));
      // Signed with a shared secret (HS256).
      final SignedJWT hmac =
          new SignedJWT(
              new JWSHeader.Builder(JWSAlgorithm.HS256).type(new JOSEObjectType("rt+jwt")).build(),
              claims("jti-1", CLIENT_ID).build());
      hmac.sign(new MACSigner(new byte[32]));
      assertNull(JWTAccessRefreshTokenIssuer.getVerifiedJwtId(hmac.serialize()));
      // Unsigned while the server signs.
      assertNull(JWTAccessRefreshTokenIssuer.getVerifiedJwtId(unsigned("rt+jwt", "jti-1")));
      // Missing jti or client_id.
      assertNull(
          JWTAccessRefreshTokenIssuer.getVerifiedJwtId(
              signedWith("rt+jwt", claims(null, CLIENT_ID).build(), TENANT)));
      assertNull(
          JWTAccessRefreshTokenIssuer.getVerifiedJwtId(
              signedWith("rt+jwt", claims("jti-1", null).build(), TENANT)));
      // Unknown client.
      assertNull(
          JWTAccessRefreshTokenIssuer.getVerifiedJwtId(
              signedWith("rt+jwt", claims("jti-1", "unknown").build(), TENANT)));
      // Control: the untouched token verifies.
      assertEquals(JWTAccessRefreshTokenIssuer.getVerifiedJwtId(valid), "jti-1");
    }
  }

  @Test
  public void rejectsRefreshTokensWhenTheApplicationCannotBeLoaded() throws Exception {
    try (MockedIdentityServer server = new MockedIdentityServer(RS256, true)) {
      final JWTAccessRefreshTokenIssuer issuer = new JWTAccessRefreshTokenIssuer();
      server.addApp(CLIENT_ID, TENANT, issuer);
      final String valid = build(issuer, user(TENANT), "jti-1", VALIDITY);
      server.failAppLookups();
      assertNull(JWTAccessRefreshTokenIssuer.getVerifiedJwtId(valid));
    }
  }

  static AuthenticatedUser user(final String tenantDomain) {
    final AuthenticatedUser user = new AuthenticatedUser();
    user.setUserName("user-1");
    user.setTenantDomain(tenantDomain);
    user.setAuthenticatedSubjectIdentifier("subject-1");
    return user;
  }

  private static String build(
      final JWTAccessRefreshTokenIssuer issuer,
      final AuthenticatedUser user,
      final String jwtId,
      final long validity)
      throws Exception {
    return issuer.buildRefreshToken(
        CLIENT_ID,
        user,
        new String[] {"profile", "openid", "email"},
        "APPLICATION_USER",
        jwtId,
        ISSUED_AT,
        validity);
  }

  private static JWTClaimsSet.Builder claims(final String jwtId, final String clientId) {
    final JWTClaimsSet.Builder builder =
        new JWTClaimsSet.Builder().subject("subject-1").issueTime(new Date(ISSUED_AT));
    if (jwtId != null) {
      builder.jwtID(jwtId);
    }
    if (clientId != null) {
      builder.claim("client_id", clientId);
    }
    return builder;
  }

  private static String signedWith(final String type, final String jwtId) throws Exception {
    return signedWith(type, claims(jwtId, CLIENT_ID).build(), "test-key");
  }

  private static String signedWith(
      final String type, final JWTClaimsSet claims, final String keyName) throws Exception {
    final JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256);
    if (type != null) {
      header.type(new JOSEObjectType(type));
    }
    final SignedJWT jwt = new SignedJWT(header.build(), claims);
    jwt.sign(new RSASSASigner(keyPair(keyName).getPrivate()));
    return jwt.serialize();
  }

  private static String unsigned(final String type, final String jwtId) {
    final PlainHeader.Builder header = new PlainHeader.Builder();
    if (type != null) {
      header.type(new JOSEObjectType(type));
    }
    return new PlainJWT(header.build(), claims(jwtId, CLIENT_ID).build()).serialize();
  }
}
