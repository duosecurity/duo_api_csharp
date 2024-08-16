/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using System.Net;
using System.Net.Security;
using duo_api_csharp.Models;
using duo_api_csharp.Classes;
using System.Net.Http.Headers;
using duo_api_csharp.SignatureTypes;
using System.Security.Cryptography.X509Certificates;

namespace duo_api_csharp
{
    /// <summary>
    /// Create a new instance of the Duo API class
    /// </summary>
    /// <param name="ikey">Duo integration key</param>
    /// <param name="skey">Duo secret key</param>
    /// <param name="host">API URL to communicate with</param>
    /// <param name="user_agent">Useragent to send to the API</param>
    public class DuoAPI(string ikey, string skey, string host, string user_agent = "DuoAPICSharp/2.0")
    {
        private const int INITIAL_BACKOFF_MS = 1000;
        private const int MAX_BACKOFF_MS = 32000;
        private const int BACKOFF_FACTOR = 2;
        private const int RATE_LIMIT_HTTP_CODE = 429;
        private bool _TLSCertificateValidation = true;

        #region Public Properties
        ///  <summary>
        /// Disables SSL certificate validation for the API calls the client makes.
        /// Incomptible with UseCustomRootCertificates since certificates will not be checked.
        /// Only available in debug builds
        /// </summary>
        public bool DisableTLSCertificateValidation
        {
            get
            {
                return _TLSCertificateValidation;
            }
            set
            {
                #if DEBUG
                _TLSCertificateValidation = value;
                #else
                throw new Exception("Disabling TLS validation is not available in release builds");
                #endif
            }
        }

        /// <summary>
        /// Override the set of Duo root certificates used for certificate pinning.  Provide a collection of acceptable root certificates.
        /// Incompatible with DisableSslCertificateValidation - if that is enabled, certificate pinning is not done at all. 
        /// </summary>
        public X509CertificateCollection? CustomRootCertificates { get; set; } = null;
        
        /// <summary>
        /// Time, after which elapsed we consider the API request to have failed and return an error response
        /// If null, the default system RequestTimeout is used
        /// </summary>
        public TimeSpan? RequestTimeout { get; set; } = null;
        #endregion Public Properties
        
        #region Public Methods
        /// <summary>
        /// Perform a Duo API call
        /// </summary>
        /// <param name="method">HTTP Method to </param>
        /// <param name="path">The API path, excluding the host</param>
        /// <param name="parameters">Parameters that make up the request</param>
        /// <param name="date">The current date and time, used to authenticate
        /// the API request. Typically, you should specify DateTime.UtcNow,
        /// but if you do not wish to rely on the system-wide clock, you may
        /// determine the current date/time by some other means.</param>
        /// <param name="signatureType">The type of signature to use to sign the request</param>
        /// <returns>Response model indicating status code and response data, if any</returns>
        /// <exception name="DuoException">Exception on unexpected error that could not be returned as part of the response model</exception>
        public DuoAPIResponse APICall(HttpMethod method, string path, Dictionary<string, string>? parameters = null, DateTime? date = null, DuoSignatureTypes signatureType = DuoSignatureTypes.Duo_SignatureTypeV4)
        {
            // Get request date
            var requestDate = date ?? DateTime.UtcNow;
            var serverRequestUri = new UriBuilder
            {
                Scheme = "https",
                Host = host,
                Path = path,
                Port = -1
            };

            // Check signature
            IDuoSignatureTypes DuoSignature;
            if( signatureType == DuoSignatureTypes.Duo_SignatureTypeV4 ) DuoSignature = new DuoSignatureV4(ikey, skey, host, requestDate);
            else if( signatureType == DuoSignatureTypes.Duo_SignatureTypeV5 ) DuoSignature = new DuoSignatureV5(ikey, skey, host, requestDate);
            else throw new DuoException("Invalid or unsupported signature type");
            
            // Get request auth and send
            var requestHeaders = DuoSignature.DefaultRequestHeaders;
            var requestAuthentication = DuoSignature.SignRequest(method, path, parameters, requestDate, requestHeaders);
            var clientResponse = _SendHTTPRequest(method, serverRequestUri.Uri, requestAuthentication, parameters, requestHeaders);
            var responseObject = new DuoAPIResponse
            {
                RequestSuccess = clientResponse.IsSuccessStatusCode,
                StatusCode = clientResponse.StatusCode
            };
            
            // Try to read data from response
            try
            {
                using var reader = new StreamReader(clientResponse.Content.ReadAsStream());
                responseObject.ResponseData = reader.ReadToEnd();
            }
            catch( Exception ) {}
            return responseObject;
        }
        
        /// <summary>
        /// Perform a Duo API call
        /// </summary>
        /// <param name="method">HTTP Method to </param>
        /// <param name="path">The API path, excluding the host</param>
        /// <param name="parameters">Parameters that make up the request</param>
        /// <param name="date">The current date and time, used to authenticate
        /// the API request. Typically, you should specify DateTime.UtcNow,
        /// but if you do not wish to rely on the system-wide clock, you may
        /// determine the current date/time by some other means.</param>
        /// <param name="signatureType">The type of signature to use to sign the request</param>
        /// <returns>Response model indicating status code and response data, if any</returns>
        /// <exception name="DuoException">Exception on unexpected error that could not be returned as part of the response model</exception>
        public async Task<DuoAPIResponse> APICallAsync(HttpMethod method, string path, Dictionary<string, string>? parameters = null, DateTime? date = null, DuoSignatureTypes signatureType = DuoSignatureTypes.Duo_SignatureTypeV4)
        {
            // Get request date
            var requestDate = date ?? DateTime.UtcNow;
            var serverRequestUri = new UriBuilder
            {
                Scheme = "https",
                Host = host,
                Path = path,
                Port = -1
            };
            
            // Check signature
            IDuoSignatureTypes DuoSignature;
            if( signatureType == DuoSignatureTypes.Duo_SignatureTypeV4 ) DuoSignature = new DuoSignatureV4(ikey, skey, host, requestDate);
            else if( signatureType == DuoSignatureTypes.Duo_SignatureTypeV5 ) DuoSignature = new DuoSignatureV5(ikey, skey, host, requestDate);
            else throw new DuoException("Invalid or unsupported signature type");
            
            // Get request auth and send
            var requestHeaders = DuoSignature.DefaultRequestHeaders;
            var requestAuthentication = DuoSignature.SignRequest(method, path, parameters, requestDate, requestHeaders);
            var clientResponse = await _SendHTTPRequestAsync(method, serverRequestUri.Uri, requestAuthentication, parameters, requestHeaders);
            var responseObject = new DuoAPIResponse
            {
                RequestSuccess = clientResponse.IsSuccessStatusCode,
                StatusCode = clientResponse.StatusCode
            };
            
            // Try to read data from response
            try
            {
                responseObject.ResponseData = await clientResponse.Content.ReadAsStringAsync();
            }
            catch( Exception ) {}
            return responseObject;
        }
        #endregion Public Methods

        #region Private Methods
        /// <summary>
        /// Send a HTTP request to the Duo Servers
        /// </summary>
        /// <param name="method">HTTP Request method</param>
        /// <param name="url">The URL, excluding the host</param>
        /// <param name="auth">The generated bearer auth token</param>
        /// <param name="requestData">Request data, mandatory for PUT and POST methods</param>
        /// <param name="duoHeaders">Any additional X-Duo headers required for the request</param>
        /// <returns>HttpResponseMessage</returns>
        /// <exception cref="DuoException">If no data is provided for PUT or POST methods</exception>
        /// <exception cref="HttpRequestException">Error on HttpRequest from dotnet</exception>
        private HttpResponseMessage _SendHTTPRequest(HttpMethod method, Uri url, string auth, Dictionary<string, string>? requestData = null, Dictionary<string, string>? duoHeaders = null)
        {
            // Setup the HttpClient. There is no reason to permit anything other than TLS1.2 and 1.3 as the API endpoints don't accept it
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls13 | SecurityProtocolType.Tls12;
            var WebRequest = new HttpClient(new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = _ServerCertificateCustomValidationCallback,
            });
            
            // Setup the request headers
            WebRequest.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", auth);
            WebRequest.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            WebRequest.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            WebRequest.DefaultRequestHeaders.UserAgent.ParseAdd(_FormatUserAgent(user_agent));
            WebRequest.Timeout = RequestTimeout ?? WebRequest.Timeout;
            
            // Add additional headers
            if( duoHeaders != null )
            {
                foreach( var (header, value) in duoHeaders )
                {
                    WebRequest.DefaultRequestHeaders.Add(header, value);
                }
            }
            
            // Formulate the request message
            var requestMessage = new HttpRequestMessage
            {
                Method = method,
                RequestUri = url
            };
            
            // Handle request data
            if( method == HttpMethod.Post || method == HttpMethod.Put )
            {
                if( requestData == null ) throw new DuoException("PUT or POST method specified but no request data");
                requestMessage.Content = new FormUrlEncodedContent(requestData);
            }

            return WebRequest.Send(requestMessage);
        }
        
        /// <summary>
        /// Send a async HTTP request to the Duo Servers
        /// </summary>
        /// <param name="method">HTTP Request method</param>
        /// <param name="url">The URL, excluding the host</param>
        /// <param name="auth">The generated bearer auth token</param>
        /// <param name="requestData">Request data, mandatory for PUT and POST methods</param>
        /// <param name="duoHeaders">Any additional X-Duo headers required for the request</param>
        /// <returns>HttpResponseMessage</returns>
        /// <exception cref="DuoException">If no data is provided for PUT or POST methods</exception>
        /// <exception cref="HttpRequestException">Error on HttpRequest from dotnet</exception>
        private async Task<HttpResponseMessage> _SendHTTPRequestAsync(HttpMethod method, Uri url, string auth, Dictionary<string, string>? requestData = null, Dictionary<string, string>? duoHeaders = null)
        {
            // Setup the HttpClient. There is no reason to permit anything other than TLS1.2 and 1.3 as the API endpoints don't accept it
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls13 | SecurityProtocolType.Tls12;
            var WebRequest = new HttpClient(new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = _ServerCertificateCustomValidationCallback,
            });
            
            // Setup the request headers
            WebRequest.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", auth);
            WebRequest.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            WebRequest.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            WebRequest.DefaultRequestHeaders.UserAgent.ParseAdd(_FormatUserAgent(user_agent));
            WebRequest.Timeout = RequestTimeout ?? WebRequest.Timeout;
            
            // Add additional headers
            if( duoHeaders != null )
            {
                foreach( var (header, value) in duoHeaders )
                {
                    WebRequest.DefaultRequestHeaders.Add(header, value);
                }
            }
            
            // Formulate the request message
            var requestMessage = new HttpRequestMessage
            {
                Method = method,
                RequestUri = url
            };
            
            // Handle request data
            if( method == HttpMethod.Post || method == HttpMethod.Put )
            {
                if( requestData == null ) throw new DuoException("PUT or POST method specified but no request data");
                requestMessage.Content = new FormUrlEncodedContent(requestData);
            }

            return await WebRequest.SendAsync(requestMessage);
        }

        /// <summary>
        /// Validate the server certificate
        /// </summary>
        private bool _ServerCertificateCustomValidationCallback(HttpRequestMessage arg1, X509Certificate2? arg2, X509Chain? arg3, SslPolicyErrors arg4)
        {
            #if DEBUG
            // Check if certificate validation is enabled
            if( !_TLSCertificateValidation )
            {
                return true;
            }
            #endif
            
            // Get the certificates
            var CertificateValidation =  ( CustomRootCertificates != null )
                ? CertificatePinnerFactory.GetCustomRootCertificatesPinner(CustomRootCertificates)
                : CertificatePinnerFactory.GetDuoCertificatePinner();
                
            // Perform cert validation
            return CertificateValidation(arg1, arg2, arg3, arg4);
        }
        
        /// Helper to format a User-Agent string with some information about
        /// the operating system / .NET runtime
        /// <param name="product_name">e.g. "FooClient/1.0"</param>
        private string _FormatUserAgent(string product_name)
        {
            return $"{product_name} ({Environment.OSVersion}; .NET {Environment.Version})";
        }
        #endregion Private Methods
    }
}
