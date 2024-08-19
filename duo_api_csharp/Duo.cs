/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using System.Net;
using System.Web;
using System.Text;
using Newtonsoft.Json;
using System.Net.Security;
using duo_api_csharp.Models;
using duo_api_csharp.Classes;
using System.Net.Http.Headers;
using duo_api_csharp.Endpoints;
using duo_api_csharp.SignatureTypes;
using System.Security.Cryptography.X509Certificates;

namespace duo_api_csharp
{
    /// <summary>
    /// Duo API class
    /// </summary>
    public class DuoAPI
    {
        private bool _TLSCertificateValidation = true;
        private readonly string user_agent;
        private readonly string ikey;
        private readonly string skey;
        private readonly string host;
        
        #region Constructor
        /// <summary>
        /// Create a new instance of the Duo API class
        /// </summary>
        /// <param name="ikey">Duo integration key</param>
        /// <param name="skey">Duo secret key</param>
        /// <param name="host">API URL to communicate with</param>
        /// <param name="user_agent">Useragent to send to the API</param>
        public DuoAPI(string ikey, string skey, string host, string user_agent = "Duo API CSharp/2.0")
        {
            this.ikey = ikey;
            this.skey = skey;
            this.host = host;
            this.user_agent = user_agent;
            Admin_v1 = new AdminAPIv1(this);
            Admin_v2 = new AdminAPIv2(this);
        }
        #endregion Constructor

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
        
        /// <summary>
        /// Admin API interface (version 1)
        /// </summary>
        public AdminAPIv1 Admin_v1 { get; init; }
        
        /// <summary>
        /// Admin API interface (version 2)
        /// </summary>
        public AdminAPIv2 Admin_v2 { get; init; }
        #endregion Public Properties
        
        #region Public Methods
        /// <summary>
        /// Perform a Duo API call, disregarding response data other than success state
        /// To return response data, specify a model to deserialise the response into with T
        /// </summary>
        /// <param name="method">HTTP Method to </param>
        /// <param name="path">The API path, excluding the host</param>
        /// <param name="param">Parameters that make up the request</param>
        /// <param name="date">The current date and time, used to authenticate
        /// the API request. Typically, you should specify DateTime.UtcNow,
        /// but if you do not wish to rely on the system-wide clock, you may
        /// determine the current date/time by some other means.</param>
        /// <param name="signatureType">The type of signature to use to sign the request</param>
        /// <returns>Response model indicating status code and response data, if any</returns>
        /// <exception name="DuoException">Exception on unexpected error that could not be returned as part of the response model</exception>
        public DuoAPIResponse APICall(
                HttpMethod method, 
                string path, 
                DuoRequestData? param = null, 
                DateTime? date = null, 
                DuoSignatureTypes signatureType = DuoSignatureTypes.Duo_SignatureTypeV5)
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
            if( signatureType == DuoSignatureTypes.Duo_SignatureTypeV2 ) DuoSignature = new DuoSignatureV2(ikey, skey, host, requestDate);
            else if( signatureType == DuoSignatureTypes.Duo_SignatureTypeV4 ) DuoSignature = new DuoSignatureV4(ikey, skey, host, requestDate);
            else if( signatureType == DuoSignatureTypes.Duo_SignatureTypeV5 ) DuoSignature = new DuoSignatureV5(ikey, skey, host, requestDate);
            else throw new DuoException("Invalid or unsupported signature type");
            
            // Except for POST,PUT and PATCH, put parameters in the URL
            if( method != HttpMethod.Post && method != HttpMethod.Put && method != HttpMethod.Patch && param is DuoParamRequestData paramData )
            {
                var queryBuilder = new StringBuilder();
                foreach( var (paramKey, paramValue) in paramData.RequestData )
                {
                    if( queryBuilder.Length != 0 ) queryBuilder.Append('&');
                    queryBuilder.Append($"{HttpUtility.UrlEncode(paramKey)}={HttpUtility.UrlEncode(paramValue)}");
                }
                serverRequestUri.Query = queryBuilder.ToString();
            }
            
            // Get request auth and send
            var requestHeaders = DuoSignature.DefaultRequestHeaders;
            var requestAuthentication = DuoSignature.SignRequest(method, path, requestDate, param, requestHeaders);
            var clientResponse = _SendHTTPRequest(method, serverRequestUri.Uri, requestAuthentication, signatureType, param, requestHeaders);
            var responseObject = new DuoAPIResponse
            {
                RequestSuccess = clientResponse.IsSuccessStatusCode,
                StatusCode = clientResponse.StatusCode
            };
            
            // Try to read data from response
            try
            {
                using var reader = new StreamReader(clientResponse.Content.ReadAsStream());
                responseObject.RawResponseData = reader.ReadToEnd();
                responseObject.ResponseData = JsonConvert.DeserializeObject<DuoResponseModel>(responseObject.RawResponseData);
            }
            catch( Exception ) {}
            return responseObject;
        }
        
        /// <summary>
        /// Perform a Duo API call, disregarding response data other than success state
        /// To return response data, specify a model to deserialise the response into with T
        /// </summary>
        /// <param name="method">HTTP Method to </param>
        /// <param name="path">The API path, excluding the host</param>
        /// <param name="param">Parameters that make up the request</param>
        /// <param name="date">The current date and time, used to authenticate
        /// the API request. Typically, you should specify DateTime.UtcNow,
        /// but if you do not wish to rely on the system-wide clock, you may
        /// determine the current date/time by some other means.</param>
        /// <param name="signatureType">The type of signature to use to sign the request</param>
        /// <returns>Response model indicating status code and response data, if any</returns>
        /// <exception name="DuoException">Exception on unexpected error that could not be returned as part of the response model</exception>
        public async Task<DuoAPIResponse> APICallAsync(
                HttpMethod method, 
                string path, 
                DuoRequestData? param = null, 
                DateTime? date = null, 
                DuoSignatureTypes signatureType = DuoSignatureTypes.Duo_SignatureTypeV5)
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
            if( signatureType == DuoSignatureTypes.Duo_SignatureTypeV2 ) DuoSignature = new DuoSignatureV2(ikey, skey, host, requestDate);
            else if( signatureType == DuoSignatureTypes.Duo_SignatureTypeV4 ) DuoSignature = new DuoSignatureV4(ikey, skey, host, requestDate);
            else if( signatureType == DuoSignatureTypes.Duo_SignatureTypeV5 ) DuoSignature = new DuoSignatureV5(ikey, skey, host, requestDate);
            else throw new DuoException("Invalid or unsupported signature type");
            
            // Except for POST,PUT and PATCH, put parameters in the URL
            if( method != HttpMethod.Post && method != HttpMethod.Put && method != HttpMethod.Patch && param is DuoParamRequestData paramData )
            {
                var queryBuilder = new StringBuilder();
                foreach( var (paramKey, paramValue) in paramData.RequestData )
                {
                    if( queryBuilder.Length != 0 ) queryBuilder.Append('&');
                    queryBuilder.Append($"{HttpUtility.UrlEncode(paramKey)}={HttpUtility.UrlEncode(paramValue)}");
                }
                serverRequestUri.Query = queryBuilder.ToString();
            }
            
            // Get request auth and send
            var requestHeaders = DuoSignature.DefaultRequestHeaders;
            var requestAuthentication = DuoSignature.SignRequest(method, path, requestDate, param, requestHeaders);
            var clientResponse = await _SendHTTPRequestAsync(method, serverRequestUri.Uri, requestAuthentication, signatureType, param, requestHeaders);
            var responseObject = new DuoAPIResponse
            {
                RequestSuccess = clientResponse.IsSuccessStatusCode,
                StatusCode = clientResponse.StatusCode
            };
            
            // Try to read data from response
            try
            {
                responseObject.RawResponseData = await clientResponse.Content.ReadAsStringAsync();
                responseObject.ResponseData = JsonConvert.DeserializeObject<DuoResponseModel>(responseObject.RawResponseData);
            }
            catch( Exception ) {}
            return responseObject;
        }
        
        /// <summary>
        /// Perform a Duo API call, disregarding response data other than success state
        /// To return response data, specify a model to deserialise the response into with T
        /// </summary>
        /// <param name="method">HTTP Method to </param>
        /// <param name="path">The API path, excluding the host</param>
        /// <param name="param">Parameters that make up the request</param>
        /// <param name="date">The current date and time, used to authenticate
        /// the API request. Typically, you should specify DateTime.UtcNow,
        /// but if you do not wish to rely on the system-wide clock, you may
        /// determine the current date/time by some other means.</param>
        /// <param name="signatureType">The type of signature to use to sign the request</param>
        /// <returns>Response model indicating status code and response data, if any</returns>
        /// <exception name="DuoException">Exception on unexpected error that could not be returned as part of the response model</exception>
        public DuoAPIResponse<T> APICall<T>(
                HttpMethod method, 
                string path, 
                DuoRequestData? param = null, 
                DateTime? date = null, 
                DuoSignatureTypes signatureType = DuoSignatureTypes.Duo_SignatureTypeV5)
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
            if( signatureType == DuoSignatureTypes.Duo_SignatureTypeV2 ) DuoSignature = new DuoSignatureV2(ikey, skey, host, requestDate);
            else if( signatureType == DuoSignatureTypes.Duo_SignatureTypeV4 ) DuoSignature = new DuoSignatureV4(ikey, skey, host, requestDate);
            else if( signatureType == DuoSignatureTypes.Duo_SignatureTypeV5 ) DuoSignature = new DuoSignatureV5(ikey, skey, host, requestDate);
            else throw new DuoException("Invalid or unsupported signature type");
            
            // Except for POST,PUT and PATCH, put parameters in the URL
            if( method != HttpMethod.Post && method != HttpMethod.Put && method != HttpMethod.Patch && param is DuoParamRequestData paramData )
            {
                var queryBuilder = new StringBuilder();
                foreach( var (paramKey, paramValue) in paramData.RequestData )
                {
                    if( queryBuilder.Length != 0 ) queryBuilder.Append('&');
                    queryBuilder.Append($"{HttpUtility.UrlEncode(paramKey)}={HttpUtility.UrlEncode(paramValue)}");
                }
                serverRequestUri.Query = queryBuilder.ToString();
            }
            
            // Get request auth and send
            var requestHeaders = DuoSignature.DefaultRequestHeaders;
            var requestAuthentication = DuoSignature.SignRequest(method, path, requestDate, param, requestHeaders);
            var clientResponse = _SendHTTPRequest(method, serverRequestUri.Uri, requestAuthentication, signatureType, param, requestHeaders);
            var responseObject = new DuoAPIResponse<T>
            {
                RequestSuccess = clientResponse.IsSuccessStatusCode,
                StatusCode = clientResponse.StatusCode
            };
            
            // Try to read data from response
            try
            {
                using var reader = new StreamReader(clientResponse.Content.ReadAsStream());
                responseObject.ResponseData = JsonConvert.DeserializeObject<DuoResponseModel<T>>(reader.ReadToEnd());
            }
            catch( Exception ) {}
            return responseObject;
        }
        
        /// <summary>
        /// Perform a Duo API call, disregarding response data other than success state
        /// To return response data, specify a model to deserialise the response into with T
        /// </summary>
        /// <param name="method">HTTP Method to </param>
        /// <param name="path">The API path, excluding the host</param>
        /// <param name="param">Parameters that make up the request</param>
        /// <param name="date">The current date and time, used to authenticate
        /// the API request. Typically, you should specify DateTime.UtcNow,
        /// but if you do not wish to rely on the system-wide clock, you may
        /// determine the current date/time by some other means.</param>
        /// <param name="signatureType">The type of signature to use to sign the request</param>
        /// <returns>Response model indicating status code and response data, if any</returns>
        /// <exception name="DuoException">Exception on unexpected error that could not be returned as part of the response model</exception>
        public async Task<DuoAPIResponse<T>> APICallAsync<T>(
                HttpMethod method, 
                string path, 
                DuoRequestData? param = null, 
                DateTime? date = null, 
                DuoSignatureTypes signatureType = DuoSignatureTypes.Duo_SignatureTypeV5)
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
            if( signatureType == DuoSignatureTypes.Duo_SignatureTypeV2 ) DuoSignature = new DuoSignatureV2(ikey, skey, host, requestDate);
            else if( signatureType == DuoSignatureTypes.Duo_SignatureTypeV4 ) DuoSignature = new DuoSignatureV4(ikey, skey, host, requestDate);
            else if( signatureType == DuoSignatureTypes.Duo_SignatureTypeV5 ) DuoSignature = new DuoSignatureV5(ikey, skey, host, requestDate);
            else throw new DuoException("Invalid or unsupported signature type");
            
            // Except for POST,PUT and PATCH, put parameters in the URL
            if( method != HttpMethod.Post && method != HttpMethod.Put && method != HttpMethod.Patch && param is DuoParamRequestData paramData )
            {
                var queryBuilder = new StringBuilder();
                foreach( var (paramKey, paramValue) in paramData.RequestData )
                {
                    if( queryBuilder.Length != 0 ) queryBuilder.Append('&');
                    queryBuilder.Append($"{HttpUtility.UrlEncode(paramKey)}={HttpUtility.UrlEncode(paramValue)}");
                }
                serverRequestUri.Query = queryBuilder.ToString();
            }
            
            // Get request auth and send
            var requestHeaders = DuoSignature.DefaultRequestHeaders;
            var requestAuthentication = DuoSignature.SignRequest(method, path, requestDate, param, requestHeaders);
            var clientResponse = await _SendHTTPRequestAsync(method, serverRequestUri.Uri, requestAuthentication, signatureType, param, requestHeaders);
            var responseObject = new DuoAPIResponse<T>
            {
                RequestSuccess = clientResponse.IsSuccessStatusCode,
                StatusCode = clientResponse.StatusCode
            };
            
            // Try to read data from response
            try
            {
                responseObject.ResponseData = JsonConvert.DeserializeObject<DuoResponseModel<T>>(await clientResponse.Content.ReadAsStringAsync());
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
        /// <param name="signatureType">The type of signature to use to sign the request</param>
        /// <param name="bodyRequestData">Request data to be placed in the request body</param>
        /// <param name="duoHeaders">Any additional headers to send with the request</param>
        /// <returns>HttpResponseMessage</returns>
        /// <exception cref="DuoException">If no data is provided for PUT or POST methods</exception>
        /// <exception cref="HttpRequestException">Error on HttpRequest from dotnet</exception>
        private HttpResponseMessage _SendHTTPRequest(HttpMethod method, Uri url, string auth, DuoSignatureTypes signatureType, DuoRequestData? bodyRequestData = null, Dictionary<string, string>? duoHeaders = null)
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
            if( method == HttpMethod.Post || method == HttpMethod.Put || method == HttpMethod.Patch )
            {
                if( signatureType is DuoSignatureTypes.Duo_SignatureTypeV4 or DuoSignatureTypes.Duo_SignatureTypeV5 )
                {
                    // requestData is JSON in the request body for Signature 4 and 5
                    if( bodyRequestData is DuoJsonRequestData jsonData && !string.IsNullOrEmpty(jsonData.RequestData) )
                    {
                        requestMessage.Content = new StringContent(jsonData.RequestData, Encoding.UTF8, jsonData.ContentTypeHeader);
                    }
                    else
                    {
                        throw new DuoException($"{method} specified but either DuoJsonRequestData was not provided or DuoJsonRequestData.RequestData was null or empty (And signaturetype was >=4)");
                    }
                }
                else
                {
                    // requestData is FormUrl encoded in the request body for Signature 2
                    if( bodyRequestData is DuoParamRequestData paramData )
                    {
                        requestMessage.Content = new FormUrlEncodedContent(paramData.RequestData);
                    }
                    else
                    {
                        throw new DuoException($"{method} specified but either DuoParamRequestData was not provided or DuoParamRequestData.RequestData was null (And signaturetype was <4)");
                    }
                }
            }
            
            // Make request and send response back to parent
            return WebRequest.Send(requestMessage);
        }
        
        /// <summary>
        /// Send a async HTTP request to the Duo Servers
        /// </summary>
        /// <param name="method">HTTP Request method</param>
        /// <param name="url">The URL, excluding the host</param>
        /// <param name="auth">The generated bearer auth token</param>
        /// <param name="signatureType">The type of signature to use to sign the request</param>
        /// <param name="bodyRequestData">Request data to be placed in the request body</param>
        /// <param name="duoHeaders">Any additional headers to send with the request</param>
        /// <returns>HttpResponseMessage</returns>
        /// <exception cref="DuoException">If no data is provided for PUT or POST methods</exception>
        /// <exception cref="HttpRequestException">Error on HttpRequest from dotnet</exception>
        private async Task<HttpResponseMessage> _SendHTTPRequestAsync(HttpMethod method, Uri url, string auth, DuoSignatureTypes signatureType, DuoRequestData? bodyRequestData = null, Dictionary<string, string>? duoHeaders = null)
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
            if( method == HttpMethod.Post || method == HttpMethod.Put || method == HttpMethod.Patch )
            {
                if( signatureType is DuoSignatureTypes.Duo_SignatureTypeV4 or DuoSignatureTypes.Duo_SignatureTypeV5 )
                {
                    // requestData is JSON in the request body for Signature 4 and 5
                    if( bodyRequestData is DuoJsonRequestData jsonData && !string.IsNullOrEmpty(jsonData.RequestData) )
                    {
                        requestMessage.Content = new StringContent(jsonData.RequestData, Encoding.UTF8, jsonData.ContentTypeHeader);
                    }
                    else
                    {
                        throw new DuoException($"{method} specified but either DuoJsonRequestData was not provided or DuoJsonRequestData.RequestData was null or empty (And signaturetype was >=4)");
                    }
                }
                else
                {
                    // requestData is FormUrl encoded in the request body for Signature 2
                    if( bodyRequestData is DuoParamRequestData paramData )
                    {
                        requestMessage.Content = new FormUrlEncodedContent(paramData.RequestData);
                    }
                    else
                    {
                        throw new DuoException($"{method} specified but either DuoParamRequestData was not provided or DuoParamRequestData.RequestData was null (And signaturetype was <4)");
                    }
                }
            }

            // Make request and send response back to parent
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
