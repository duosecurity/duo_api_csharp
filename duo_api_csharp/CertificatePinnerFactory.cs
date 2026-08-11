/*
 * Copyright (c) 2022 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 */

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System;

namespace Duo
{
    public class CertificatePinnerFactory
    {
        private readonly X509Certificate2Collection _rootCerts;
        private readonly HashSet<string> _pinnedSpkiHashes;

        public CertificatePinnerFactory(X509CertificateCollection rootCerts)
        {
            // Normalize to X509Certificate2 so we always have access to RawData (for
            // SPKI hashing) and, on .NET 5+, a CustomTrustStore-compatible collection.
            _rootCerts = new X509Certificate2Collection();
            foreach (X509Certificate cert in rootCerts)
            {
                _rootCerts.Add(new X509Certificate2(cert));
            }
            _pinnedSpkiHashes = ComputePinnedSpkiHashes(_rootCerts);
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
        /// Pin only to the configured root certificates, and reject connections to any other roots.
        ///
        /// The connection is only allowed if the presented chain is anchored in one of the
        /// pinned roots. Anchoring is checked by matching the SHA-256 hash of each presented
        /// certificate's SubjectPublicKeyInfo (SPKI) against the pinned set, walking the entire
        /// chain. Matching on the SPKI rather than on the full certificate DER makes pinning
        /// robust against cross-signing: the self-signed and cross-signed forms of the same CA
        /// share a public key (and therefore an SPKI hash) even though their certificate DER
        /// differs. Walking the full chain means it does not matter where in the chain the OS
        /// placed the pinned key.
        ///
        /// On .NET 5+ the presented chain is additionally re-validated against only the pinned
        /// roots using <see cref="X509ChainTrustMode.CustomRootTrust"/>, so trust does not depend
        /// on the OS trust store containing the pinned root.
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

            // If the regular certificate checking process failed, fail.
            // We require the platform to have validated signatures, expiry, name, etc.
            // first; pinning then restricts which roots are acceptable.
            if (sslPolicyErrors != SslPolicyErrors.None)
            {
                return false;
            }

            // Double check the platform-built chain reported no errors.
            if (!chain.ChainStatus.All(status => status.Status == X509ChainStatusFlags.NoError))
            {
                return false;
            }

#if NET5_0_OR_GREATER
            // On .NET 5+, restrict the trust anchors to exactly the pinned roots via a
            // custom trust store. This removes any dependence on the OS trust store and
            // enforces pinning at chain-validation time rather than only by inspection.
            if (!ValidatesAgainstCustomTrustStore(certificate, chain))
            {
                return false;
            }
#endif

            // Walk the full chain and require that at least one presented certificate's
            // SPKI hash is in the pinned set. This is the primary check on .NET Framework
            // and a defense-in-depth check on .NET 5+.
            return ChainContainsPinnedSpki(chain);
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

#if NET5_0_OR_GREATER
        /// <summary>
        /// Re-validate the presented chain against only the pinned roots, using
        /// CustomRootTrust so the OS trust store is not consulted for the trust anchor.
        /// </summary>
        private bool ValidatesAgainstCustomTrustStore(X509Certificate certificate, X509Chain presentedChain)
        {
            using (var customChain = new X509Chain())
            {
                customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                // Re-validate in the same temporal context the platform used, so this
                // check neither loosens nor tightens expiry relative to the original
                // validation (which has already run and reported no errors). Only copy
                // an explicitly-set verification time; leaving it unset (the default)
                // lets the new chain validate as of "now".
                DateTime presentedTime = presentedChain.ChainPolicy.VerificationTime;
                if (presentedTime != default(DateTime) && presentedTime != DateTime.MinValue)
                {
                    customChain.ChainPolicy.VerificationTime = presentedTime;
                }
                customChain.ChainPolicy.VerificationFlags = presentedChain.ChainPolicy.VerificationFlags;
                customChain.ChainPolicy.CustomTrustStore.Clear();
                customChain.ChainPolicy.CustomTrustStore.AddRange(_rootCerts);

                // Supply the intermediates the server presented so the custom chain can
                // build the same path up to one of our pinned roots.
                foreach (X509ChainElement element in presentedChain.ChainElements)
                {
                    customChain.ChainPolicy.ExtraStore.Add(element.Certificate);
                }

                var leaf = certificate as X509Certificate2 ?? new X509Certificate2(certificate);
                return customChain.Build(leaf);
            }
        }
#endif

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
