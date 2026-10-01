package org.wso2.support.sample.jwttokenissuer.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.support.sample.jwttokenissuer.JWTAccessRefreshTokenIssuer;
import org.wso2.support.sample.jwttokenissuer.JWTRefreshTokenInterceptor;
import org.wso2.support.sample.jwttokenissuer.JWTTokenIssuerConstants;

/**
 * Registers {@link JWTRefreshTokenInterceptor} as an OAuth event interceptor.
 *
 * <p>The token issuer is not an OSGi service: the OAuth component instantiates it by class name
 * from the token types configured in deployment.toml, through its DynamicImport-Package.
 *
 * <p>Do not rely on the activation message to confirm deployment. When the bundle is activated
 * during server startup, the message is often missing from the log even though activation
 * succeeded. Check the bundle state from the OSGi console instead (see the README).
 */
@Component(name = "custom.jwt.access.refresh.token.issuer.bundle", immediate = true)
public class BundleComponent {
  private static final Log log = LogFactory.getLog(BundleComponent.class);

  private ServiceRegistration<OAuthEventInterceptor> interceptorRegistration;

  @Activate
  protected void activate(final ComponentContext context) {
    interceptorRegistration =
        context
            .getBundleContext()
            .registerService(OAuthEventInterceptor.class, new JWTRefreshTokenInterceptor(), null);
    log.info(
        "Custom JWT access and refresh token issuer bundle activated. Register "
            + JWTAccessRefreshTokenIssuer.class.getName()
            + " under token type '"
            + JWTTokenIssuerConstants.TOKEN_TYPE_NAME
            + "' and enable "
            + JWTRefreshTokenInterceptor.class.getName()
            + " as an event listener in deployment.toml to use it.");
  }

  @Deactivate
  protected void deactivate(final ComponentContext ignored) {
    if (interceptorRegistration != null) {
      interceptorRegistration.unregister();
      interceptorRegistration = null;
    }
    log.info("Custom JWT access and refresh token issuer bundle deactivated.");
  }
}
