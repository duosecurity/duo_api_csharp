/*
 * Copyright (c) 2022 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 */

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System;

namespace Duo
{
    public class CertificatePinnerFactory
    {
        // id-kp-serverAuth (RFC 5280 section 4.2.1.12)
        private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

        private readonly X509Certificate2Collection _trustAnchors;
        private readonly HashSet<string> _pinnedSpkiHashes;
        private readonly DateTime? _verificationTime;

        public CertificatePinnerFactory(X509CertificateCollection rootCerts)
            : this(rootCerts, null)
        {
        }

        /// <param name="rootCerts">The certificates to anchor on</param>
        /// <param name="verificationTime">
        /// The time to validate the rebuilt chain at; the current time if null. Only tests
        /// should set this, so that they can use recorded certificates that later expire.
        /// </param>
        internal CertificatePinnerFactory(X509CertificateCollection rootCerts, DateTime? verificationTime)
        {
            _trustAnchors = ToCertificate2Collection(rootCerts);
            _pinnedSpkiHashes = ComputePinnedSpkiHashes(_trustAnchors);
            _verificationTime = verificationTime;
        }

        /// <summary>
        /// Get a certificate pinner that ensures only connections to a specific list of root certificates are allowed
        /// </summary>
        /// <returns>A Duo certificate pinner for use in an HttpWebRequest</returns>
        public static RemoteCertificateValidationCallback GetDuoCertificatePinner()
        {
            return new CertificatePinnerFactory(GetDuoCertCollection()).GetPinner();
        }
        /// <summary>
        /// Get a certificate pinner that ensures only connections to the provided root certificates are allowed
        /// </summary>
        /// <remarks>
        /// The supplied certificates replace Duo's bundled certificates as the trust anchors:
        /// the OS trust store is not required to contain them. Supply root certificates. An
        /// intermediate is only honored when the OS trust store also validates the chain,
        /// because a chain validated without the OS must end at one of the supplied
        /// certificates.
        /// </remarks>
        /// <returns>A certificate pinner for use in an HttpWebRequest</returns>
        public static RemoteCertificateValidationCallback GetCustomRootCertificatesPinner(X509CertificateCollection rootCerts)
        {
            return new CertificatePinnerFactory(rootCerts).GetPinner();
        }


        /// <summary>
        /// Get a certificate "pinner" that effectively disables SSL certificate validation
        /// </summary>
        /// <returns></returns>
        public static RemoteCertificateValidationCallback GetCertificateDisabler()
        {
            return (httpRequestMessage, certificate, chain, sslPolicyErrors) => true;
        }

        /// <summary>
        /// Get a validator that disables certificate pinning while still enforcing TLS
        /// verification via the OS trust store. The connection is allowed only when the
        /// certificate chain passes the platform's default validation (no SSL policy errors).
        /// </summary>
        /// <returns>A validator that relies on the OS trust store for use in an HttpWebRequest</returns>
        public static RemoteCertificateValidationCallback GetOsTrustStoreValidator()
        {
            return (httpRequestMessage, certificate, chain, sslPolicyErrors) => sslPolicyErrors == SslPolicyErrors.None;
        }

        internal RemoteCertificateValidationCallback GetPinner()
        {
            return PinCertificate;
        }

        /// <summary>
        /// Allow only connections whose certificate chains to one of the configured
        /// certificates (Duo's bundled ca_certs.pem by default). The OS trust store is not
        /// required to contain them.
        ///
        /// A connection is allowed in either of two ways:
        ///
        /// 1. Fast path: the platform validated the chain against the OS trust store with no
        ///    errors, and the SHA-256 hash of some chain certificate's SubjectPublicKeyInfo
        ///    (SPKI) is in the pinned set. Matching on the SPKI rather than on the full
        ///    certificate DER makes this robust against cross-signing: the self-signed and
        ///    cross-signed forms of the same CA share a public key (and therefore an SPKI
        ///    hash) even though their certificate DER differs. The whole chain is walked
        ///    because Windows and Linux build different chains for the same server.
        ///
        /// 2. Otherwise, the chain is rebuilt with the configured certificates as the trust
        ///    anchors (see <see cref="ChainsToTrustAnchor"/>). This is what lets the client
        ///    connect when the OS trust store is missing or has a stale copy of Duo's roots,
        ///    without having to download them.
        ///
        /// A hostname mismatch or a missing certificate is always rejected.
        /// </summary>
        /// <param name="request">The actual request (unused)</param>
        /// <param name="certificate">The server certificate presented to the connection</param>
        /// <param name="chain">The full certificate chain presented to the connection</param>
        /// <param name="sslPolicyErrors">The current result of the certificate checks</param>
        /// <returns>true if the connection should be allowed, false otherwise</returns>
        internal bool PinCertificate(object request,
                                    X509Certificate certificate,
                                    X509Chain chain,
                                    SslPolicyErrors sslPolicyErrors)
        {
            // If there's no server certificate or chain, fail
            if (certificate == null || chain == null)
            {
                return false;
            }

            // The platform checks the hostname separately from the chain, so a name
            // mismatch (or no certificate at all) is fatal whatever the chain looks like.
            // Only chain errors can be resolved by validating against our own anchors.
            if ((sslPolicyErrors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None)
            {
                return false;
            }

            // Fast path: the OS validated the chain and it contains a pinned key.
            if (sslPolicyErrors == SslPolicyErrors.None &&
                chain.ChainStatus.All(status => status.Status == X509ChainStatusFlags.NoError) &&
                ChainContainsPinnedSpki(chain))
            {
                return true;
            }

            // The OS could not validate the chain (e.g. Duo's root is missing from its trust
            // store), or validated it to a root we do not pin: decide using our own anchors.
            return ChainsToTrustAnchor(certificate, chain);
        }

        /// <summary>
        /// Rebuild the server's chain with the configured certificates as the only trust
        /// anchors, and return true if it is valid and ends at one of them.
        ///
        /// .NET Framework has no way to replace the trust store of an X509Chain, so this uses
        /// the standard pattern for a custom trust anchor: put the anchors in the ExtraStore so
        /// the chain can be completed without the OS store, allow an unknown root, then require
        /// that the root the chain actually ended at is byte-for-byte one of the anchors. The
        /// platform still checks every signature, validity period, basic constraint, name
        /// constraint and key usage, the serverAuth extended key usage, and the OS distrust
        /// list (ExplicitDistrust).
        /// </summary>
        private bool ChainsToTrustAnchor(X509Certificate certificate, X509Chain presentedChain)
        {
            var leaf = certificate as X509Certificate2 ?? new X509Certificate2(certificate);

            using (var chain = new X509Chain())
            {
                X509ChainPolicy policy = chain.ChainPolicy;
                policy.ExtraStore.AddRange(_trustAnchors);
                policy.ExtraStore.AddRange(PresentedIntermediates(presentedChain));
                // Tolerate only UntrustedRoot. In particular this does not ignore expiry,
                // usage or constraint errors. It does let Build() return true for a chain
                // that could not be completed (PartialChain), so the status is checked below
                // rather than relying on the return value.
                policy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                policy.ApplicationPolicy.Add(new Oid(ServerAuthOid));
                // Match the revocation behavior of the platform's own check of this connection.
                policy.RevocationMode = ServicePointManager.CheckCertificateRevocationList
                    ? X509RevocationMode.Online
                    : X509RevocationMode.NoCheck;
                policy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                policy.VerificationTime = _verificationTime ?? DateTime.Now;
#if NET5_0_OR_GREATER
                // Everything needed to reach an anchor is either sent by the server or
                // bundled, so never wait on a download that could only produce a chain that
                // is rejected anyway.
                policy.DisableCertificateDownloads = true;
#endif

                chain.Build(leaf);

                if (chain.ChainElements.Count == 0 ||
                    !chain.ChainStatus.All(status => IsAcceptableStatus(status.Status)))
                {
                    return false;
                }
                foreach (X509ChainElement element in chain.ChainElements)
                {
                    if (!element.ChainElementStatus.All(status => IsAcceptableStatus(status.Status)))
                    {
                        return false;
                    }
                }

                // UntrustedRoot only says the chain ended at some self-signed certificate.
                // It must be one of ours: matching a pinned key alone is not enough, since a
                // pinned key re-wrapped in a certificate from another root would bypass the
                // real CA certificate's validity and constraints.
                X509Certificate2 root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                return IsTrustAnchor(root);
            }
        }

        /// <summary>
        /// The only chain statuses accepted on a rebuilt chain. UntrustedRoot means the chain
        /// ended at a self-signed certificate that the OS does not trust, which is expected
        /// when it is one of our anchors. PartialChain and every other error are rejected.
        /// </summary>
        private static bool IsAcceptableStatus(X509ChainStatusFlags status)
        {
            return status == X509ChainStatusFlags.NoError ||
                   status == X509ChainStatusFlags.UntrustedRoot;
        }

        /// <summary>
        /// The CA certificates the server presented, for completing the rebuilt chain. Any
        /// self-signed certificate is left out so that only our anchors can end the chain.
        /// </summary>
        private static X509Certificate2Collection PresentedIntermediates(X509Chain presentedChain)
        {
            var candidates = new List<X509Certificate2>();
            // .NET 5+ passes the certificates the server sent in the ExtraStore; .NET
            // Framework only exposes the chain the OS built from them.
            candidates.AddRange(presentedChain.ChainPolicy.ExtraStore.Cast<X509Certificate2>());
            candidates.AddRange(presentedChain.ChainElements.Cast<X509ChainElement>()
                                                            .Skip(1)
                                                            .Select(element => element.Certificate));

            var intermediates = new X509Certificate2Collection();
            foreach (X509Certificate2 cert in candidates)
            {
                if (!cert.SubjectName.RawData.SequenceEqual(cert.IssuerName.RawData))
                {
                    intermediates.Add(cert);
                }
            }
            return intermediates;
        }

        private bool IsTrustAnchor(X509Certificate2 cert)
        {
            return _trustAnchors.Cast<X509Certificate2>().Any(anchor => anchor.RawData.SequenceEqual(cert.RawData));
        }

        /// <summary>
        /// Return true if any certificate in the presented chain has a SubjectPublicKeyInfo
        /// whose SHA-256 hash is in the pinned set.
        /// </summary>
        private bool ChainContainsPinnedSpki(X509Chain chain)
        {
            foreach (X509ChainElement element in chain.ChainElements)
            {
                string spkiHash;
                try
                {
                    spkiHash = SpkiPinning.ComputeSpkiSha256(element.Certificate.RawData);
                }
                catch
                {
                    // A certificate we cannot parse cannot match a pin; skip it.
                    continue;
                }

                if (_pinnedSpkiHashes.Contains(spkiHash))
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Compute the set of pinned SPKI SHA-256 hashes from the configured root certificates.
        /// </summary>
        private static HashSet<string> ComputePinnedSpkiHashes(X509Certificate2Collection rootCerts)
        {
            var hashes = new HashSet<string>();
            foreach (X509Certificate2 cert in rootCerts)
            {
                hashes.Add(SpkiPinning.ComputeSpkiSha256(cert.RawData));
            }
            return hashes;
        }

        private static X509Certificate2Collection ToCertificate2Collection(X509CertificateCollection certs)
        {
            var result = new X509Certificate2Collection();
            foreach (X509Certificate cert in certs)
            {
                result.Add(cert as X509Certificate2 ?? new X509Certificate2(cert));
            }
            return result;
        }

        /// <summary>
        /// Get the root certificates allowed by Duo in a usable form
        /// </summary>
        /// <returns>A X509CertificateCollection of the allowed root certificates</returns>
        internal static X509CertificateCollection GetDuoCertCollection()
        {
            var certs = ReadCertsFromFile();

            X509CertificateCollection coll = new X509CertificateCollection();
            foreach (string oneCert in certs)
            {
                if (!string.IsNullOrWhiteSpace(oneCert))
                {
                    byte[] der = DecodePemCertificate(oneCert);
                    if (der != null)
                    {
                        coll.Add(new X509Certificate2(der));
                    }
                }
            }
            return coll;
        }

        /// <summary>
        /// Extract the DER bytes of a single certificate from a PEM block that may be
        /// surrounded by comment lines. This is parsed explicitly (rather than relying
        /// on the X509Certificate byte[] constructor to interpret PEM) so certificate
        /// loading behaves identically across .NET Framework and .NET 5+.
        /// </summary>
        private static byte[] DecodePemCertificate(string pem)
        {
            const string begin = "-----BEGIN CERTIFICATE-----";
            const string end = "-----END CERTIFICATE-----";

            int start = pem.IndexOf(begin, StringComparison.Ordinal);
            if (start < 0)
            {
                return null;
            }
            start += begin.Length;

            int stop = pem.IndexOf(end, start, StringComparison.Ordinal);
            if (stop < 0)
            {
                return null;
            }

            string base64 = pem.Substring(start, stop - start)
                               .Replace("\r", "")
                               .Replace("\n", "")
                               .Trim();
            return Convert.FromBase64String(base64);
        }

        /// <summary>
        /// Read the embedded Duo ca_certs.pem certificates file to get an array of certificate strings
        /// </summary>
        /// <returns>The Duo root CA certificates as strings</returns>
        internal static string[] ReadCertsFromFile()
        {
            var certs = "";
            using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("duo_api_csharp.ca_certs.pem"))
            using (StreamReader reader = new StreamReader(stream))
            {
                certs = reader.ReadToEnd();
            }
            var splitOn = "-----DUO_CERT-----";
            return certs.Split(new string[] { splitOn }, int.MaxValue, StringSplitOptions.None);
        }
    }
}
