package org.wso2.support.sample.jwttokenissuer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

/**
 * Issues JWT access tokens and JWT refresh tokens.
 *
 * <p>Access tokens are issued exactly as by {@link JWTTokenIssuer}. Refresh tokens are generated,
 * stored and looked up by Identity Server as the usual opaque value, which becomes the "jti" of
 * the JWT the client receives: {@link JWTRefreshTokenInterceptor} signs the JWT when the token
 * endpoint returns a refresh token, and turns a JWT presented by a client back into its "jti".
 * Rotation, replay rejection, revocation, expiry and introspection therefore work exactly as they
 * do for opaque refresh tokens.
 *
 * <p>Applications opt in by using the token type this class is registered under. Applications on
 * other token types are not affected.
 */
public class JWTAccessRefreshTokenIssuer extends JWTTokenIssuer {

  private static final Log log = LogFactory.getLog(JWTAccessRefreshTokenIssuer.class);

  public JWTAccessRefreshTokenIssuer() throws IdentityOAuth2Exception {
    super();
  }

  /**
   * Signs the JWT form of a refresh token.
   *
   * @param jwtId the refresh token value Identity Server stored
   * @param validityMillis refresh token validity; a negative value means the token does not
   *     expire, as Identity Server treats it, and the JWT then has no "exp" claim
   */
  String buildRefreshToken(
      final String clientId,
      final AuthenticatedUser user,
      final String[] scopes,
      final String userType,
      final String jwtId,
      final long issuedAtMillis,
      final long validityMillis)
      throws IdentityOAuth2Exception, InvalidOAuthClientException, JOSEException {

    final OAuthAppDO app = OAuth2Util.getAppInformationByClientId(clientId);
    final String appTenantDomain = app.getAppOwner().getTenantDomain();
    final String issuer = OAuth2Util.getIdTokenIssuer(appTenantDomain);

    final JWTClaimsSet.Builder claims =
        new JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(user != null ? user.getAuthenticatedSubjectIdentifier() : clientId)
            // A refresh token is only ever presented to the token endpoint. Using the issuer as the
            // audience (not the client ID) also keeps it from passing as an ID token.
            .audience(issuer)
            .claim(JWTTokenIssuerConstants.AUTHORIZED_PARTY_CLAIM, clientId)
            .claim(JWTTokenIssuerConstants.CLIENT_ID_CLAIM, clientId)
            .issueTime(new Date(issuedAtMillis))
            .notBeforeTime(new Date(issuedAtMillis))
            .jwtID(jwtId);
    if (validityMillis >= 0) {
      claims.expirationTime(new Date(issuedAtMillis + validityMillis));
    }
    final String scopeClaim = scopeClaimValue(scopes);
    if (scopeClaim != null) {
      claims.claim(JWTTokenIssuerConstants.SCOPE_CLAIM, scopeClaim);
    }
    if (userType != null) {
      claims.claim(JWTTokenIssuerConstants.AUTHORIZED_USER_TYPE_CLAIM, userType);
    }

    final String signingTenantDomain =
        resolveSigningTenantDomain(appTenantDomain, user != null ? user.getTenantDomain() : null);
    if (!OAuthServerConfiguration.getInstance().getUseSPTenantDomainValue()) {
      // Same "realm" claim JWTTokenIssuer adds to access tokens signed with the user's tenant key.
      claims.claim(
          OAuthConstants.OIDCClaims.REALM,
          Collections.singletonMap(OAuthConstants.OIDCClaims.SIGNING_TENANT, signingTenantDomain));
    }
    return sign(claims.build(), signingTenantDomain);
  }

  /**
   * Returns the "jti" of a JWT refresh token after verifying its signature with the key it must
   * have been signed with. Expiry and revocation are not checked here: Identity Server checks both
   * against the stored token once the JWT is turned back into its "jti".
   *
   * <p>An unsigned refresh token is accepted only while the server is configured to issue unsigned
   * JWTs, which is when this issuer produces them.
   *
   * @return the "jti", or null when the value is not a JWT refresh token or cannot be verified
   */
  static String getVerifiedJwtId(final String value) {
    final JWT parsed = parseRefreshTokenJWT(value);
    if (parsed == null) {
      return null;
    }
    try {
      final JWTClaimsSet claims = parsed.getJWTClaimsSet();
      final String jwtId = claims.getJWTID();
      final String clientId = claims.getStringClaim(JWTTokenIssuerConstants.CLIENT_ID_CLAIM);
      if (jwtId == null || clientId == null) {
        log.debug("The JWT refresh token has no jti or client_id claim.");
        return null;
      }
      if (parsed instanceof PlainJWT) {
        if (isUnsignedConfigured()) {
          return jwtId;
        }
        log.debug("Unsigned JWT refresh token rejected: the server is configured to sign JWTs.");
        return null;
      }
      final SignedJWT jwt = (SignedJWT) parsed;
      if (!JWSAlgorithm.Family.RSA.contains(jwt.getHeader().getAlgorithm())) {
        log.debug("The JWT refresh token is not signed with an RSA algorithm.");
        return null;
      }

      final OAuthAppDO app = OAuth2Util.getAppInformationByClientId(clientId);
      final String signingTenantDomain =
          resolveSigningTenantDomain(
              app.getAppOwner().getTenantDomain(), signingTenantClaim(claims));
      final Certificate certificate =
          OAuth2Util.getCertificate(
              signingTenantDomain, IdentityTenantUtil.getTenantId(signingTenantDomain));
      final PublicKey publicKey = certificate.getPublicKey();
      if (!(publicKey instanceof RSAPublicKey)) {
        log.debug("The signing certificate does not hold an RSA public key.");
        return null;
      }
      if (!jwt.verify(new RSASSAVerifier((RSAPublicKey) publicKey))) {
        log.debug("The signature of the JWT refresh token is not valid.");
        return null;
      }
      return jwtId;
    } catch (final ParseException
        | JOSEException
        | IdentityOAuth2Exception
        | InvalidOAuthClientException e) {
      if (log.isDebugEnabled()) {
        log.debug("The JWT refresh token could not be verified.", e);
      }
      return null;
    }
  }

  /**
   * Parses the value as a JWT refresh token (signed or unsigned), without verifying it.
   *
   * @return the parsed token, or null when the value is not a JWT with the refresh token type
   *     header (for example, an opaque refresh token or an access token)
   */
  static JWT parseRefreshTokenJWT(final String value) {
    if (!isJWT(value)) {
      return null;
    }
    try {
      final JWT jwt = JWTParser.parse(value);
      if (!(jwt instanceof SignedJWT) && !(jwt instanceof PlainJWT)) {
        return null;
      }
      final JOSEObjectType type = jwt.getHeader().getType();
      if (type == null
          || !JWTTokenIssuerConstants.REFRESH_TOKEN_TYP_HEADER.equals(type.getType())) {
        return null;
      }
      return jwt;
    } catch (final ParseException e) {
      return null;
    }
  }

  private static boolean isUnsignedConfigured() {
    return JWTTokenIssuerConstants.UNSIGNED_ALGORITHM.equals(
        OAuthServerConfiguration.getInstance().getSignatureAlgorithm());
  }

  /** Same check Identity Server uses: a JWT has three parts separated by periods. */
  static boolean isJWT(final String value) {
    return value != null && value.chars().filter(c -> c == '.').count() == 2;
  }

  /** Scopes in a stable order, so the claim does not depend on the order they were granted in. */
  static String scopeClaimValue(final String[] scopes) {
    if (scopes == null || scopes.length == 0) {
      return null;
    }
    return Arrays.stream(scopes).distinct().sorted().collect(Collectors.joining(" "));
  }

  private static String signingTenantClaim(final JWTClaimsSet claims) {
    final Object realm = claims.getClaim(OAuthConstants.OIDCClaims.REALM);
    if (realm instanceof Map) {
      final Object tenant = ((Map<?, ?>) realm).get(OAuthConstants.OIDCClaims.SIGNING_TENANT);
      return tenant != null ? tenant.toString() : null;
    }
    return null;
  }

  /** Same rule JWTTokenIssuer applies to access tokens, so both are signed with the same key. */
  private static String resolveSigningTenantDomain(
      final String appTenantDomain, final String userTenantDomain) throws IdentityOAuth2Exception {
    if (OAuthServerConfiguration.getInstance().getUseSPTenantDomainValue()) {
      return appTenantDomain;
    }
    if (userTenantDomain == null) {
      throw new IdentityOAuth2Exception("Cannot resolve the user tenant domain of the token.");
    }
    return userTenantDomain;
  }

  private String sign(final JWTClaimsSet claims, final String tenantDomain)
      throws IdentityOAuth2Exception, JOSEException {
    final JOSEObjectType type = new JOSEObjectType(JWTTokenIssuerConstants.REFRESH_TOKEN_TYP_HEADER);
    if (isUnsignedConfigured()) {
      // Same as JWTTokenIssuer, which issues unsigned access tokens with this configuration.
      return new PlainJWT(new PlainHeader.Builder().type(type).build(), claims).serialize();
    }
    final JWSAlgorithm algorithm =
        (JWSAlgorithm)
            mapSignatureAlgorithm(OAuthServerConfiguration.getInstance().getSignatureAlgorithm());
    if (!JWSAlgorithm.Family.RSA.contains(algorithm)) {
      throw new IdentityOAuth2Exception(
          "JWT refresh tokens support RSA signature algorithms only. Configured: " + algorithm);
    }

    final int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
    final JWSHeader header =
        new JWSHeader.Builder(algorithm)
            .type(type)
            .keyID(
                OAuth2Util.getKID(
                    OAuth2Util.getCertificate(tenantDomain, tenantId), algorithm, tenantDomain))
            .x509CertThumbprint(new Base64URL(OAuth2Util.getThumbPrint(tenantDomain, tenantId)))
            .build();

    final Key privateKey = OAuth2Util.getPrivateKey(tenantDomain, tenantId);
    final SignedJWT jwt = new SignedJWT(header, claims);
    jwt.sign(OAuth2Util.createJWSSigner((RSAPrivateKey) privateKey));
    return jwt.serialize();
  }
}
