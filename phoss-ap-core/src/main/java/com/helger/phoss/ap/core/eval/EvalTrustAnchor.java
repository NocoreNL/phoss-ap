/*
 * EVAL-ONLY, NON-CONFORMANT — never use against the real Peppol network.
 * Licensed under the Apache License, Version 2.0 (same as phoss-ap).
 */
package com.helger.phoss.ap.core.eval;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.helger.base.exception.InitializationException;
import com.helger.base.string.StringHelper;
import com.helger.peppol.security.PeppolTrustedCA;
import com.helger.peppol.servicedomain.EPeppolNetwork;
import com.helger.security.certificate.TrustedCAChecker;

/**
 * EVAL-ONLY. Resolves the AP-certificate {@link TrustedCAChecker}. Returns the stock
 * {@link PeppolTrustedCA} checker unchanged when {@code eval.trusted-ca.path} is unset or on
 * production; otherwise a checker trusting the PEM CA(s) at that path. NON-CONFORMANT.
 *
 * @author NocoreNL (PP1a eval fork)
 */
public final class EvalTrustAnchor
{
  private EvalTrustAnchor ()
  {}

  @NonNull
  public static TrustedCAChecker resolveApCaChecker (@Nullable final String sEvalTrustedCaPath,
                                                     @NonNull final EPeppolNetwork eStage)
  {
    if (eStage.isProduction ())
      return PeppolTrustedCA.peppolProductionAP ();
    final String sPath = sEvalTrustedCaPath == null ? null : sEvalTrustedCaPath.trim ();
    if (StringHelper.hasNoText (sPath))
      return PeppolTrustedCA.peppolTestAP ();

    final List <X509Certificate> aEvalCerts = _loadPem (sPath);
    return TrustedCAChecker.builder ()
                           .trustedCACertificates (aEvalCerts.toArray (new X509Certificate [0]))
                           .build ();
  }

  @NonNull
  private static List <X509Certificate> _loadPem (@NonNull final String sPath)
  {
    final Path aPath = Paths.get (sPath);
    if (!Files.isReadable (aPath))
      throw new InitializationException ("eval.trusted-ca.path is set but unreadable: " + sPath);
    try (final InputStream aIS = Files.newInputStream (aPath))
    {
      final Collection <? extends Certificate> aCerts = CertificateFactory.getInstance ("X.509")
                                                                          .generateCertificates (aIS);
      if (aCerts.isEmpty ())
        throw new InitializationException ("eval.trusted-ca.path has no X.509 certificate: " + sPath);
      final List <X509Certificate> ret = new ArrayList <> ();
      for (final Certificate c : aCerts)
        ret.add ((X509Certificate) c);
      return ret;
    }
    catch (final InitializationException ex)
    {
      throw ex;
    }
    catch (final Exception ex)
    {
      throw new InitializationException ("Failed to parse eval.trusted-ca.path PEM: " + sPath, ex);
    }
  }
}
