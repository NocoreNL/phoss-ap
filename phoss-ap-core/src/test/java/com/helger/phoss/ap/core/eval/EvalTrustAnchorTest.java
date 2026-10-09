package com.helger.phoss.ap.core.eval;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;

import org.junit.Test;

import com.helger.base.exception.InitializationException;
import com.helger.base.state.ETriState;
import com.helger.peppol.security.PeppolTrustedCA;
import com.helger.peppol.servicedomain.EPeppolNetwork;
import com.helger.security.certificate.TrustedCAChecker;
import com.helger.security.revocation.ERevocationCheckMode;

/** EVAL-ONLY. Unit tests for the trust-anchor factory. */
public final class EvalTrustAnchorTest
{
  private static final String CA = resPath ("eval-ca.pem");
  private static final OffsetDateTime NOW = OffsetDateTime.now ();

  private static String resPath (final String sName)
  {
    return EvalTrustAnchorTest.class.getResource ("/eval/" + sName).getFile ();
  }

  private static X509Certificate load (final String sName) throws Exception
  {
    try (final InputStream aIS = EvalTrustAnchorTest.class.getResourceAsStream ("/eval/" + sName))
    {
      return (X509Certificate) CertificateFactory.getInstance ("X.509").generateCertificate (aIS);
    }
  }

  @Test
  public void testUnsetReturnsStockTestChecker ()
  {
    // Review Focus #1: unset => identical stock instance (test stage)
    assertSame (PeppolTrustedCA.peppolTestAP (), EvalTrustAnchor.resolveApCaChecker (null, EPeppolNetwork.TEST));
    assertSame (PeppolTrustedCA.peppolTestAP (), EvalTrustAnchor.resolveApCaChecker ("   ", EPeppolNetwork.TEST));
  }

  @Test
  public void testProductionIgnoresEvalPath ()
  {
    // Review Focus #2: prod never honors the eval anchor
    assertSame (PeppolTrustedCA.peppolProductionAP (),
                EvalTrustAnchor.resolveApCaChecker (CA, EPeppolNetwork.PRODUCTION));
  }

  @Test
  public void testSetOnTestTrustsEvalCaAndRejectsOther () throws Exception
  {
    final TrustedCAChecker aChecker = EvalTrustAnchor.resolveApCaChecker (CA, EPeppolNetwork.TEST);
    assertNotSame (PeppolTrustedCA.peppolTestAP (), aChecker);
    assertFalse ("eval CA must accept a leaf it signed",
                 aChecker.checkCertificate (load ("eval-leaf.pem"), NOW, ETriState.FALSE, ERevocationCheckMode.NONE)
                         .isInvalid ());
    assertTrue ("eval CA must still reject an unrelated self-signed cert",
                aChecker.checkCertificate (load ("other-selfsigned.pem"), NOW, ETriState.FALSE, ERevocationCheckMode.NONE)
                        .isInvalid ());
  }

  @Test
  public void testMissingPemThrows ()
  {
    try
    {
      EvalTrustAnchor.resolveApCaChecker ("/no/such/eval-ca.pem", EPeppolNetwork.TEST);
      fail ("Expected InitializationException for a missing PEM");
    }
    catch (final InitializationException ex)
    { /* expected */ }
  }
}
