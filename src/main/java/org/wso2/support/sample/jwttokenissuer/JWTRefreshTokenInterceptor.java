package org.wso2.support.sample.jwttokenissuer;

import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

/**
 * Converts refresh tokens between the value Identity Server stores and the JWT the client holds.
 *
 * <ul>
 *   <li>Token responses: for applications whose token issuer is {@link
 *       JWTAccessRefreshTokenIssuer}, the refresh token is replaced with a signed JWT whose "jti" is
 *       the stored value. The issue time and validity come from the token request context, where
 *       Identity Server records the values it stored for the refresh token, including when it
 *       returns an existing one.
 *   <li>Refresh grant, revocation and introspection: a JWT refresh token with a valid signature is
 *       replaced with its "jti" before Identity Server looks it up. This does not depend on the
 *       application's current token type, so tokens issued before a change of type keep working.
 *       Any other value is left unchanged and handled as usual.
 * </ul>
 *
 * <p>Registered as an OSGi service by the bundle component, and enabled through an event listener
 * entry in deployment.toml (see {@link AbstractOAuthEventInterceptor#isEnabled()}).
 */
public class JWTRefreshTokenInterceptor extends AbstractOAuthEventInterceptor {

  private static final Log log = LogFactory.getLog(JWTRefreshTokenInterceptor.class);

  @Override
  public void onPreTokenRenewal(
      final OAuth2AccessTokenReqDTO tokenReqDTO,
      final OAuthTokenReqMessageContext tokReqMsgCtx,
      final Map<String, Object> params) {
    final String jwtId = JWTAccessRefreshTokenIssuer.getVerifiedJwtId(tokenReqDTO.getRefreshToken());
    if (jwtId != null) {
      tokenReqDTO.setRefreshToken(jwtId);
    }
  }

  @Override
  public void onPostTokenIssue(
      final OAuth2AccessTokenReqDTO tokenReqDTO,
      final OAuth2AccessTokenRespDTO tokenRespDTO,
      final OAuthTokenReqMessageContext tokReqMsgCtx,
      final Map<String, Object> params) {
    replaceWithJWT(tokenReqDTO, tokenRespDTO, tokReqMsgCtx);
  }

  @Override
  public void onPostTokenRenewal(
      final OAuth2AccessTokenReqDTO tokenReqDTO,
      final OAuth2AccessTokenRespDTO tokenRespDTO,
      final OAuthTokenReqMessageContext tokReqMsgCtx,
      final Map<String, Object> params) {
    replaceWithJWT(tokenReqDTO, tokenRespDTO, tokReqMsgCtx);
  }

  @Override
  public void onPreTokenRevocationByClient(
      final OAuthRevocationRequestDTO revokeRequestDTO, final Map<String, Object> params) {
    final String jwtId = JWTAccessRefreshTokenIssuer.getVerifiedJwtId(revokeRequestDTO.getToken());
    if (jwtId != null) {
      revokeRequestDTO.setToken(jwtId);
    }
  }

  /** Called for introspection and for access token validation (for example, UserInfo). */
  @Override
  public void onPreTokenValidation(
      final OAuth2TokenValidationRequestDTO validationReqDTO, final Map<String, Object> params) {
    final OAuth2TokenValidationRequestDTO.OAuth2AccessToken token =
        validationReqDTO.getAccessToken();
    if (token == null) {
      return;
    }
    final String jwtId = JWTAccessRefreshTokenIssuer.getVerifiedJwtId(token.getIdentifier());
    if (jwtId != null) {
      token.setIdentifier(jwtId);
    }
  }

  private void replaceWithJWT(
      final OAuth2AccessTokenReqDTO tokenReqDTO,
      final OAuth2AccessTokenRespDTO tokenRespDTO,
      final OAuthTokenReqMessageContext tokReqMsgCtx) {

    if (tokenRespDTO == null || tokenRespDTO.isError()) {
      return;
    }
    final String refreshToken = tokenRespDTO.getRefreshToken();
    if (refreshToken == null
        || refreshToken.isEmpty()
        || JWTAccessRefreshTokenIssuer.isJWT(refreshToken)) {
      return;
    }
    final JWTAccessRefreshTokenIssuer issuer = getIssuer(tokenReqDTO.getClientId());
    if (issuer == null) {
      return;
    }
    try {
      if (tokReqMsgCtx.getRefreshTokenIssuedTime() <= 0) {
        throw new IdentityOAuth2Exception("The refresh token issue time is not available.");
      }
      tokenRespDTO.setRefreshToken(
          issuer.buildRefreshToken(
              tokenReqDTO.getClientId(),
              tokReqMsgCtx.getAuthorizedUser(),
              tokReqMsgCtx.getScope(),
              (String) tokReqMsgCtx.getProperty(OAuthConstants.UserType.USER_TYPE),
              refreshToken,
              tokReqMsgCtx.getRefreshTokenIssuedTime(),
              tokReqMsgCtx.getRefreshTokenvalidityPeriod()));
    } catch (final Exception e) {
      // Fail the request rather than return an opaque refresh token to a client that expects a JWT.
      log.error(
          "Error while building the JWT refresh token for client: " + tokenReqDTO.getClientId(), e);
      tokenRespDTO.setRefreshToken(null);
      tokenRespDTO.setError(true);
      tokenRespDTO.setErrorCode(OAuth2ErrorCodes.SERVER_ERROR);
      tokenRespDTO.setErrorMsg("Server Error");
    }
  }

  /**
   * @return the application's token issuer when it is {@link JWTAccessRefreshTokenIssuer}, or null
   *     for applications on any other token type
   */
  private static JWTAccessRefreshTokenIssuer getIssuer(final String clientId) {
    try {
      final OauthTokenIssuer issuer =
          OAuth2Util.getOAuthTokenIssuerForOAuthApp(
              OAuth2Util.getAppInformationByClientId(clientId));
      if (issuer instanceof JWTAccessRefreshTokenIssuer) {
        return (JWTAccessRefreshTokenIssuer) issuer;
      }
      if (log.isDebugEnabled()) {
        log.debug(
            "Refresh token left unchanged for client: "
                + clientId
                + ". Its token issuer is "
                + (issuer != null ? issuer.getClass().getName() : null));
      }
      return null;
    } catch (final IdentityOAuth2Exception | InvalidOAuthClientException e) {
      log.error("Error while resolving the token issuer of client: " + clientId, e);
      return null;
    }
  }
}
