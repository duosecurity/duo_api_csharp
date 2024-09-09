/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using System.Text;
using System.Reflection;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace duo_api_csharp.Classes
{
    /// <summary>
    /// Create an instance of the CertificatePinner
    /// For general use, use one of the static methods to create an instance rather than the constructur
    /// </summary>
    /// <param name="rootCerts">Certificates to validate against</param>
    public class CertificatePinnerFactory(X509CertificateCollection rootCerts)
    {
        #region Public Static Methods
        /// <summary>
        /// Get a certificate pinner that ensures only connections to a specific list of root certificates are allowed
        /// </summary>
        /// <returns>A Duo certificate pinner for use in an HttpWebRequest</returns>
        public static RemoteCertificateValidationCallback GetDuoCertificatePinner()
        {
            return new CertificatePinnerFactory(_GetDuoCertCollection())._GetPinner();
        }
        
        /// <summary>
        /// Get a certificate pinner that ensures only connections to the provided root certificates are allowed
        /// </summary>
        /// <returns>A certificate pinner for use in an HttpWebRequest</returns>
        public static RemoteCertificateValidationCallback GetCustomRootCertificatesPinner(X509CertificateCollection rootCerts)
        {
            return new CertificatePinnerFactory(rootCerts)._GetPinner();
        }

        /// <summary>
        /// Get a certificate "pinner" that effectively disables SSL certificate validation
        /// </summary>
        /// <returns></returns>
        public static RemoteCertificateValidationCallback GetCertificateDisabler()
        {
            return (_, _, _, _) => true;
        }
        #endregion Public Static Methods

        #region Internal Methods
        internal RemoteCertificateValidationCallback _GetPinner()
        {
            // Return the delegate of our callback
            // Calls from dotnet for validation for certificates will be handled by the delegate below
            return _PinCertificateCallback;
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
        internal bool _PinCertificateCallback(object request,
            X509Certificate? certificate,
            X509Chain? chain,
            SslPolicyErrors sslPolicyErrors)
        {
            // If there's no server certificate or chain, fail
            if( certificate == null || chain == null )
            {
                return false;
            }

            // If the regular certificate checking process failed, fail
            // we want everything to be valid, but then just restrict the acceptable root certificates
            if( sslPolicyErrors != SslPolicyErrors.None )
            {
                return false;
            }

            // Double check everything's valid and grab the root certificate (and double check it's valid)
            if( chain.ChainStatus.Any(status => status.Status != X509ChainStatusFlags.NoError) )
            {
                return false;
            }
            
            var chainLength = chain.ChainElements.Count;
            var rootCert = chain.ChainElements[chainLength - 1].Certificate;
            
            // Check that the root certificate is in the allowed list
            return rootCert.Verify() && rootCerts.Contains(rootCert);
        }

        /// <summary>
        /// Get the root certificates allowed by Duo in a usable form
        /// </summary>
        /// <returns>A X509CertificateCollection of the allowed root certificates</returns>
        internal static X509CertificateCollection _GetDuoCertCollection()
        {
            var certs = _ReadCertsFromFile();
            var coll = new X509CertificateCollection();
            foreach( var oneCert in certs )
            {
                if( !string.IsNullOrWhiteSpace(oneCert) )
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
        /// <param name="resource_name">The name of the resource in the assembly to retrieve</param>
        /// <returns>The Duo root CA certificates as strings</returns>
        internal static string[] _ReadCertsFromFile(string resource_name = "duo_api_csharp.Resources.ca_certs.pem")
        {
            try
            {
                using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource_name);
                using var reader = (stream != null) ? new StreamReader(stream) : null;
                if( reader != null )
                {
                    var certs = reader.ReadToEnd();
                    return certs.Split(["-----DUO_CERT-----"], int.MaxValue, StringSplitOptions.None);
                }

                throw new ApplicationException("Unable to read the embedded certificate file from the assembly. The read reqeuest returned null");
            }
            catch( Exception Ex )
            {
                throw new ApplicationException($"Unable to read the embedded certificate file from the assembly. The read reqeuest returned {Ex.Message}", Ex);
            }
        }
        #endregion Internal Methods
    }
}