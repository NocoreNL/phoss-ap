package com.helger.phoss.ap.core.outbound;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;

import org.junit.After;
import org.junit.Test;

import com.helger.base.state.ETriState;
import com.helger.config.ConfigFactory;
import com.helger.config.fallback.ConfigWithFallback;
import com.helger.config.fallback.IConfigWithFallback;
import com.helger.config.source.MultiConfigurationValueProvider;
import com.helger.config.source.appl.ConfigurationSourceFunction;
import com.helger.peppol.security.PeppolTrustedCA;
import com.helger.peppol.servicedomain.EPeppolNetwork;
import com.helger.phoss.ap.api.config.APConfigProvider;
import com.helger.phoss.ap.api.config.APConfigurationProperties;
import com.helger.security.certificate.TrustedCAChecker;
import com.helger.security.revocation.ERevocationCheckMode;

/** EVAL-ONLY. Outbound must resolve the same checker as startup. */
public final class OutboundOrchestratorEvalTrustTest
{
  private static X509Certificate load (final String sName) throws Exception
  {
    try (final InputStream aIS = OutboundOrchestratorEvalTrustTest.class.getResourceAsStream ("/eval/" + sName))
    {
      return (X509Certificate) CertificateFactory.getInstance ("X.509").generateCertificate (aIS);
    }
  }

  private static final IConfigWithFallback ORIGINAL = APConfigProvider.getConfig ();

  private static void setEvalPath (final String sPath)
  {
    final MultiConfigurationValueProvider aVP = ConfigFactory.createDefaultValueProvider ();
    if (sPath != null)
      aVP.addConfigurationSource (new ConfigurationSourceFunction (k -> APConfigurationProperties.EVAL_TRUSTED_CA_PATH.equals (k)
                                                                                                                    ? sPath
                                                                                                                    : null),
                                  1000);
    APConfigProvider.setConfig (new ConfigWithFallback (aVP));
  }

  @After
  public void after ()
  {
    APConfigProvider.setConfig (ORIGINAL);
  }

  @Test
  public void testUnsetIsVanilla ()
  {
    setEvalPath (null);
    // Review Focus #1 (outbound): disabled fork ⇒ exact stock instance
    assertSame (PeppolTrustedCA.peppolTestAP (), OutboundOrchestrator.resolveApCaChecker (EPeppolNetwork.TEST));
  }

  @Test
  public void testSetTrustsEvalCa () throws Exception
  {
    setEvalPath (OutboundOrchestratorEvalTrustTest.class.getResource ("/eval/eval-ca.pem").getFile ());
    final TrustedCAChecker aChecker = OutboundOrchestrator.resolveApCaChecker (EPeppolNetwork.TEST);
    assertFalse (aChecker.checkCertificate (load ("eval-leaf.pem"), OffsetDateTime.now (), ETriState.UNDEFINED, ERevocationCheckMode.NONE)
                         .isInvalid ());
  }
}
