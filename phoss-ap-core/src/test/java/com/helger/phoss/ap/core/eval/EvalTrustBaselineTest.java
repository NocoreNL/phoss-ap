package com.helger.phoss.ap.core.eval;

import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;

import org.junit.Test;

import com.helger.base.state.ETriState;
import com.helger.peppol.security.PeppolTrustedCA;
import com.helger.security.certificate.ECertificateCheckResult;
import com.helger.security.revocation.ERevocationCheckMode;

/** Characterization: vanilla phoss-ap rejects a non-Peppol AP certificate. EVAL-ONLY module. */
public final class EvalTrustBaselineTest
{
  private static X509Certificate _load (final String sRes) throws Exception
  {
    try (final InputStream aIS = EvalTrustBaselineTest.class.getResourceAsStream (sRes))
    {
      return (X509Certificate) CertificateFactory.getInstance ("X.509").generateCertificate (aIS);
    }
  }

  @Test
  public void testStockTestApCheckerRejectsNonPeppolCert () throws Exception
  {
    final X509Certificate aOther = _load ("/eval/other-selfsigned.pem");
    final ECertificateCheckResult e = PeppolTrustedCA.peppolTestAP ()
                                                     .checkCertificate (aOther,
                                                                        OffsetDateTime.now (),
                                                                        ETriState.UNDEFINED,
                                                                        ERevocationCheckMode.NONE);
    assertTrue ("A non-Peppol self-signed cert must be rejected by the stock checker", e.isInvalid ());
  }
}
