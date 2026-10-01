package org.wso2.support.sample.jwttokenissuer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSASigner;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.mockito.MockedStatic;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

/**
 * Stands in for the Identity Server infrastructure the extension calls statically: the OAuth server
 * configuration, application and token issuer lookups, tenant IDs, and each tenant's signing key
 * and certificate. Everything else (the extension classes, JWTTokenIssuer and the OAuth DTOs) is
 * the real code.
 *
 * <p>Static mocks only apply to the thread that created them, so each thread that calls the
 * extension needs its own instance. Keys are shared by all instances.
 */
final class MockedIdentityServer implements AutoCloseable {

  static final String SUPER_TENANT = "carbon.super";
  static final String TENANT = "example.com";
  static final String OTHER_TENANT = "other.example.com";
  static final String RS256 = "SHA256withRSA";

  private static final Map<String, KeyPair> KEYS = new ConcurrentHashMap<>();
  private static final Map<String, Integer> TENANT_IDS = new ConcurrentHashMap<>();

  static {
    // Identity Server registers BouncyCastle; PS256 signing depends on it.
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    TENANT_IDS.put(SUPER_TENANT, -1234);
    TENANT_IDS.put(TENANT, 1);
    TENANT_IDS.put(OTHER_TENANT, 2);
  }

  private final OAuthServerConfiguration serverConfiguration = mock(OAuthServerConfiguration.class);
  private final Map<String, OAuthAppDO> apps = new ConcurrentHashMap<>();
  private final Map<String, OauthTokenIssuer> issuers = new ConcurrentHashMap<>();
  private final Map<String, Certificate> certificates = new ConcurrentHashMap<>();
  private final MockedStatic<OAuthServerConfiguration> configurationMock;
  private final MockedStatic<IdentityTenantUtil> tenantMock;
  private final MockedStatic<OAuth2Util> utilMock;

  MockedIdentityServer(final String signatureAlgorithm, final boolean signWithAppTenant) {
    // Created up front: stubbing a mock inside another mock's answer is not supported.
    for (final String tenant : TENANT_IDS.keySet()) {
      final Certificate certificate = mock(Certificate.class);
      when(certificate.getPublicKey()).thenReturn(keyPair(tenant).getPublic());
      certificates.put(tenant, certificate);
    }
    when(serverConfiguration.getSignatureAlgorithm()).thenReturn(signatureAlgorithm);
    when(serverConfiguration.getUseSPTenantDomainValue()).thenReturn(signWithAppTenant);

    configurationMock = mockStatic(OAuthServerConfiguration.class);
    configurationMock.when(OAuthServerConfiguration::getInstance).thenReturn(serverConfiguration);

    tenantMock = mockStatic(IdentityTenantUtil.class);
    tenantMock
        .when(() -> IdentityTenantUtil.getTenantId(anyString()))
        .thenAnswer(invocation -> TENANT_IDS.get(invocation.<String>getArgument(0)));

    utilMock = mockStatic(OAuth2Util.class);
    utilMock
        .when(() -> OAuth2Util.getAppInformationByClientId(anyString()))
        .thenAnswer(
            invocation -> {
              final OAuthAppDO app = apps.get(invocation.<String>getArgument(0));
              if (app == null) {
                throw new InvalidOAuthClientException("Unknown client.");
              }
              return app;
            });
    utilMock
        .when(() -> OAuth2Util.getOAuthTokenIssuerForOAuthApp(any(OAuthAppDO.class)))
        .thenAnswer(
            invocation -> issuers.get(invocation.<OAuthAppDO>getArgument(0).getOauthConsumerKey()));
    utilMock
        .when(() -> OAuth2Util.getIdTokenIssuer(anyString()))
        .thenAnswer(invocation -> issuerUrl(invocation.getArgument(0)));
    utilMock
        .when(() -> OAuth2Util.getCertificate(anyString(), anyInt()))
        .thenAnswer(invocation -> certificate(invocation.getArgument(0)));
    utilMock
        .when(() -> OAuth2Util.getPrivateKey(anyString(), anyInt()))
        .thenAnswer(invocation -> keyPair(invocation.getArgument(0)).getPrivate());
    utilMock
        .when(() -> OAuth2Util.getKID(any(Certificate.class), any(JWSAlgorithm.class), anyString()))
        .thenAnswer(invocation -> "kid-" + invocation.getArgument(2));
    utilMock
        .when(() -> OAuth2Util.getThumbPrint(anyString(), anyInt()))
        .thenAnswer(invocation -> "thumbprint-" + invocation.getArgument(0));
    utilMock
        .when(() -> OAuth2Util.createJWSSigner(any(RSAPrivateKey.class)))
        .thenAnswer(invocation -> new RSASSASigner((PrivateKey) invocation.getArgument(0)));
  }

  /** Registers an application owned by the tenant and served by the issuer. */
  OAuthAppDO addApp(final String clientId, final String tenantDomain, final OauthTokenIssuer issuer) {
    final OAuthAppDO app = new OAuthAppDO();
    app.setOauthConsumerKey(clientId);
    final AuthenticatedUser owner = new AuthenticatedUser();
    owner.setUserName("admin");
    owner.setTenantDomain(tenantDomain);
    app.setAppOwner(owner);
    apps.put(clientId, app);
    if (issuer != null) {
      issuers.put(clientId, issuer);
    }
    return app;
  }

  /** Makes the application lookup fail with a server error, as a database failure would. */
  void failAppLookups() {
    utilMock
        .when(() -> OAuth2Util.getAppInformationByClientId(anyString()))
        .thenThrow(new IdentityOAuth2Exception("Database unavailable."));
  }

  /** Makes the private key lookup fail, as a missing or broken keystore would. */
  void failPrivateKeyLookups() {
    utilMock
        .when(() -> OAuth2Util.getPrivateKey(anyString(), anyInt()))
        .thenThrow(new IdentityOAuth2Exception("Keystore unavailable."));
  }

  static String issuerUrl(final String tenantDomain) {
    return SUPER_TENANT.equals(tenantDomain)
        ? "https://localhost:9443/oauth2/token"
        : "https://localhost:9443/t/" + tenantDomain + "/oauth2/token";
  }

  static KeyPair keyPair(final String name) {
    return KEYS.computeIfAbsent(
        name,
        ignored -> {
          try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
          } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
          }
        });
  }

  private Certificate certificate(final String tenantDomain) {
    return certificates.get(tenantDomain);
  }

  @Override
  public void close() {
    utilMock.close();
    tenantMock.close();
    configurationMock.close();
  }
}
