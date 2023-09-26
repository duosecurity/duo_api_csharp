/*
 * Copyright (c) 2022 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 */

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
        private readonly X509CertificateCollection _rootCerts;

        public CertificatePinnerFactory(X509CertificateCollection rootCerts)
        {
            _rootCerts = rootCerts;
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

        internal RemoteCertificateValidationCallback GetPinner()
        {
            return PinCertificate;
        }

        /// <summary>
        /// Pin only to specified root certificates, and reject connections to any other roots.
        /// NB that the certificate and chain have already been checked, and the status of that check is available
        /// in the chain ChainStatus and overall SslPolicyErrors.
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

            // If the regular certificate checking process failed, fail
            // we want everything to be valid, but then just restrict the acceptable root certificates
            if (sslPolicyErrors != SslPolicyErrors.None)
            {
                return false;
            }

            // Double check everything's valid and grab the root certificate (and double check it's valid)
            if (!chain.ChainStatus.All(status => status.Status == X509ChainStatusFlags.NoError))
            {
                return false;
            }
            var chainLength = chain.ChainElements.Count;
            var rootCert = chain.ChainElements[chainLength - 1].Certificate;
            if (!rootCert.Verify())
            {
                return false;
            }

            // Check that the root certificate is in the allowed list
            if (!_rootCerts.Contains(rootCert))
            {
                return false;
            }

            return true;
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
                    var bytes = Encoding.UTF8.GetBytes(oneCert);
                    coll.Add(new X509Certificate(bytes));
                }
            }
            return coll;
        }

        /// <summary>
        /// Read the embedded Duo ca_certs.pem certificates file to get an array of certificate strings
        /// </summary>
        /// <returns>The Duo root CA certificates as strings</returns>
        internal static string[] ReadCertsFromFile()
        {
            var certs = "";
            using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"{Assembly.GetExecutingAssembly().GetName().Name}.ca_certs.pem"))
            using (StreamReader reader = new StreamReader(stream))
            {
                certs = reader.ReadToEnd();
            }
            var splitOn = "-----DUO_CERT-----";
            return certs.Split(new string[] { splitOn }, int.MaxValue, StringSplitOptions.None);
        }
    }
}