package com.helger.phoss.ap.core.servlet;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.helger.base.exception.InitializationException;
import com.helger.base.state.ETriState;
import com.helger.peppol.servicedomain.EPeppolNetwork;
import com.helger.phase4.peppol.servlet.Phase4PeppolDefaultReceiverConfiguration;
import com.helger.phoss.ap.api.config.APConfigurationProperties;
import com.helger.security.certificate.ECertificateCheckResult;
import com.helger.security.certificate.TrustedCAChecker;
import com.helger.security.revocation.CertificateRevocationCheckerDefaults;
import com.helger.security.revocation.ERevocationCheckMode;

/** EVAL-ONLY. The startup check must accept an eval-CA cert when configured, else reject. */
public final class APServletInitEvalTrustTest
{
  private ERevocationCheckMode m_aOldMode;
  private TrustedCAChecker m_aOldChecker;

  private static String evalCaPath ()
  {
    return APServletInitEvalTrustTest.class.getResource ("/eval/eval-ca.pem").getFile ();
  }

  private static X509Certificate load (final String sName) throws Exception
  {
    try (final InputStream aIS = APServletInitEvalTrustTest.class.getResourceAsStream ("/eval/" + sName))
    {
      return (X509Certificate) CertificateFactory.getInstance ("X.509").generateCertificate (aIS);
    }
  }

  @Before
  public void before ()
  {
    m_aOldChecker = Phase4PeppolDefaultReceiverConfiguration.getAPCAChecker ();
    m_aOldMode = CertificateRevocationCheckerDefaults.getRevocationCheckMode ();
    CertificateRevocationCheckerDefaults.setRevocationCheckMode (ERevocationCheckMode.NONE);
  }

  @After
  public void after ()
  {
    CertificateRevocationCheckerDefaults.setRevocationCheckMode (m_aOldMode);
    Phase4PeppolDefaultReceiverConfiguration.setAPCAChecker (m_aOldChecker);
    System.clearProperty (APConfigurationProperties.EVAL_TRUSTED_CA_PATH);
  }

  @Test
  public void testEvalCertAcceptedWhenConfigured () throws Exception
  {
    System.setProperty (APConfigurationProperties.EVAL_TRUSTED_CA_PATH, evalCaPath ());
    // Must not throw, and the registered inbound checker must accept the eval leaf
    APServletInit.checkAndRegisterApCaChecker (load ("eval-leaf.pem"), EPeppolNetwork.TEST);
    final ECertificateCheckResult e = Phase4PeppolDefaultReceiverConfiguration.getAPCAChecker ()
                                                                              .checkCertificate (load ("eval-leaf.pem"),
                                                                                                 OffsetDateTime.now (),
                                                                                                 ETriState.UNDEFINED,
                                                                                                 ERevocationCheckMode.NONE);
    assertFalse ("inbound checker must inherit the eval anchor", e.isInvalid ());
  }

  @Test
  public void testNonPeppolCertRejectedWhenUnset () throws Exception
  {
    System.clearProperty (APConfigurationProperties.EVAL_TRUSTED_CA_PATH);
    try
    {
      APServletInit.checkAndRegisterApCaChecker (load ("other-selfsigned.pem"), EPeppolNetwork.TEST);
      fail ("Expected InitializationException for a non-Peppol cert with eval unset");
    }
    catch (final InitializationException ex)
    { /* expected - vanilla behavior preserved */ }
  }
}
