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
using System;

namespace Duo
{
    public class CertificatePinnerFactory
    {
        private readonly HashSet<string> _pinnedSpkiHashes;

        public CertificatePinnerFactory(X509CertificateCollection rootCerts)
        {
            _pinnedSpkiHashes = ComputePinnedSpkiHashes(rootCerts);
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
        /// A connection is allowed when any certificate in the validated chain shares a public
        /// key with one of the supplied certificates, so an intermediate may be pinned as well
        /// as a root.
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
        /// Pin only to the configured certificates, and reject connections that do not
        /// involve one of them.
        ///
        /// The connection is allowed only if the SHA-256 hash of some presented certificate's
        /// SubjectPublicKeyInfo (SPKI) is in the pinned set, checked by walking the entire
        /// chain. Matching on the SPKI rather than on the full certificate DER makes pinning
        /// robust against cross-signing: the self-signed and cross-signed forms of the same CA
        /// share a public key (and therefore an SPKI hash) even though their certificate DER
        /// differs. Walking the full chain means it does not matter where in the chain the OS
        /// placed the pinned key -- which is the whole point, since Windows and Linux build
        /// different chains for the same server.
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
            // first; pinning then restricts which keys are acceptable.
            if (sslPolicyErrors != SslPolicyErrors.None)
            {
                return false;
            }

            // Double check the platform-built chain reported no errors.
            if (!chain.ChainStatus.All(status => status.Status == X509ChainStatusFlags.NoError))
            {
                return false;
            }

            // The pin check itself: walk the full chain and require that at least one
            // presented certificate's SPKI hash is in the pinned set.
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

        /// <summary>
        /// Compute the set of pinned SPKI SHA-256 hashes from the configured root certificates.
        /// </summary>
        private static HashSet<string> ComputePinnedSpkiHashes(X509CertificateCollection rootCerts)
        {
            var hashes = new HashSet<string>();
            foreach (X509Certificate cert in rootCerts)
            {
                hashes.Add(SpkiPinning.ComputeSpkiSha256(cert.GetRawCertData()));
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
