package org.wso2.support.sample.jwttokenissuer;

/** Constants for the JWT access and refresh token issuer. */
public final class JWTTokenIssuerConstants {

  /** Token type name the issuer is registered under in deployment.toml. */
  public static final String TOKEN_TYPE_NAME = "JWT_AT_RT";

  /**
   * JOSE "typ" header for refresh tokens. Deliberately not "at+jwt" (RFC 9068 access tokens), so a
   * resource server that validates access tokens by type cannot accept a refresh token. Same value
   * WSO2 Identity Server uses for its own JWT refresh tokens in later versions.
   */
  public static final String REFRESH_TOKEN_TYP_HEADER = "rt+jwt";

  /**
   * Claim carrying the granted scopes as a space-separated string, the standard "scope" claim
   * (RFC 8693) that JWTTokenIssuer also uses for access tokens.
   */
  public static final String SCOPE_CLAIM = "scope";

  /** Configured signature algorithm value that makes Identity Server issue unsigned JWTs. */
  public static final String UNSIGNED_ALGORITHM = "NONE";

  public static final String CLIENT_ID_CLAIM = "client_id";
  public static final String AUTHORIZED_PARTY_CLAIM = "azp";
  public static final String AUTHORIZED_USER_TYPE_CLAIM = "aut";

  private JWTTokenIssuerConstants() {}
}
