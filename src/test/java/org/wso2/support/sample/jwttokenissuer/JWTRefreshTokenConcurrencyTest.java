package org.wso2.support.sample.jwttokenissuer;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.wso2.support.sample.jwttokenissuer.JWTRefreshTokenInterceptorTest.context;
import static org.wso2.support.sample.jwttokenissuer.JWTRefreshTokenInterceptorTest.request;
import static org.wso2.support.sample.jwttokenissuer.JWTRefreshTokenInterceptorTest.response;
import static org.wso2.support.sample.jwttokenissuer.MockedIdentityServer.OTHER_TENANT;
import static org.wso2.support.sample.jwttokenissuer.MockedIdentityServer.RS256;
import static org.wso2.support.sample.jwttokenissuer.MockedIdentityServer.TENANT;

import com.nimbusds.jwt.SignedJWT;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

/**
 * Identity Server calls one interceptor instance and one issuer instance from every request
 * thread. Many threads issue and present refresh tokens at once, for two tenants, and every token
 * must come back to exactly the value that was stored for it.
 */
public class JWTRefreshTokenConcurrencyTest {

  private static final int THREADS = 16;
  private static final int TOKENS_PER_THREAD = 200;

  @Test(timeOut = 120000)
  public void issuesAndReadsBackRefreshTokensFromManyThreads() throws Exception {
    final JWTRefreshTokenInterceptor interceptor = new JWTRefreshTokenInterceptor();
    final JWTAccessRefreshTokenIssuer issuer;
    try (MockedIdentityServer ignored = new MockedIdentityServer(RS256, false)) {
      issuer = new JWTAccessRefreshTokenIssuer();
    }

    final Queue<String> failures = new ConcurrentLinkedQueue<>();
    final Set<String> jwtIds = ConcurrentHashMap.newKeySet();
    final CountDownLatch start = new CountDownLatch(1);
    final ExecutorService pool = Executors.newFixedThreadPool(THREADS);
    final List<Future<?>> workers = new ArrayList<>();
    for (int t = 0; t < THREADS; t++) {
      final String userTenant = t % 2 == 0 ? TENANT : OTHER_TENANT;
      workers.add(
          pool.submit(
              () -> {
                // Static mocks are per thread; the interceptor and issuer are shared.
                try (MockedIdentityServer server = new MockedIdentityServer(RS256, false)) {
                  server.addApp(JWTRefreshTokenInterceptorTest.JWT_APP, TENANT, issuer);
                  start.await();
                  for (int i = 0; i < TOKENS_PER_THREAD; i++) {
                    final String stored = UUID.randomUUID().toString();

                    final OAuth2AccessTokenReqDTO issueRequest =
                        request(JWTRefreshTokenInterceptorTest.JWT_APP, null, true);
                    final OAuth2AccessTokenRespDTO issued = response(stored);
                    interceptor.onPostTokenIssue(
                        issueRequest, issued, context(issueRequest, userTenant), new HashMap<>());
                    final String jwt = issued.getRefreshToken();
                    final String jwtId = SignedJWT.parse(jwt).getJWTClaimsSet().getJWTID();

                    final OAuth2AccessTokenReqDTO refresh =
                        request(JWTRefreshTokenInterceptorTest.JWT_APP, jwt, true);
                    interceptor.onPreTokenRenewal(
                        refresh, new OAuthTokenReqMessageContext(refresh), new HashMap<>());

                    if (!stored.equals(jwtId) || !stored.equals(refresh.getRefreshToken())) {
                      failures.add(stored + " -> " + jwtId + " -> " + refresh.getRefreshToken());
                    }
                    jwtIds.add(jwtId);
                  }
                }
                return null;
              }));
    }
    start.countDown();
    for (final Future<?> worker : workers) {
      worker.get();
    }
    pool.shutdown();
    assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

    assertTrue(failures.isEmpty(), "Mismatched tokens: " + failures);
    assertEquals(jwtIds.size(), THREADS * TOKENS_PER_THREAD);
  }
}
