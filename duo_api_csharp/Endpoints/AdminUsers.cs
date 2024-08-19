/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using Newtonsoft.Json;
using duo_api_csharp.Models;
using duo_api_csharp.Classes;
using duo_api_csharp.Models.v1;

namespace duo_api_csharp.Endpoints
{
    public sealed partial class AdminAPIv1(DuoAPI duo_api)
    {
        /// <summary>
        /// Duo Admin API - Users
        /// https://duo.com/docs/adminapi#users
        /// </summary>
        public AdminAPIv1_Users Users { get; } = new(duo_api);
    }
    
    public sealed class AdminAPIv1_Users
    {
        #region Internal constructor
        private readonly DuoAPI duo_api;
        internal AdminAPIv1_Users(DuoAPI duo_api)
        {
            this.duo_api = duo_api;
            JsonConvert.DefaultSettings = () => new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore
            };
        }
        #endregion Internal constructor
        
        #region Retrieve Users
        /// <summary>
        /// Returns a paged list of users. To fetch all results, call repeatedly with the offset parameter as long as the result metadata has a next_offset value.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="limit">
        /// The maximum number of records returned.
        /// Default: 100; Max: 300
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <param name="user_id_list">
        /// A list of user ids used to fetch multiple users by user_id. You can provide up to 100 user_id values.
        /// If you provide this parameter, you must not provide the username, email or user_name_list parameters. The limit and offset parameters will be ignored.
        /// </param>
        /// <param name="username_list">
        /// A list of usernames used to fetch multiple users by username. You can provide up to 100 usernames.
        /// If you provide this parameter, you must not provide the username, email or user_name_list parameters. The limit and offset parameters will be ignored.
        /// </param>
        /// <returns>User response model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoUserResponseModel>>> GetUsers(int limit = 100, int offset = 0, string[]? user_id_list = null, string[]? username_list = null)
        {
            // Check paging bounds
            if( limit is > 300 or < 1 ) limit = 100;
            if( offset < 1 ) offset = 0;
            
            // Request parameters
            var requestParam = new DuoParamRequestData
            {
                RequestData = new Dictionary<string, string>
                {
                    { "offset", $"{offset}" },
                    { "limit", $"{limit}" }
                }
            };
            
            if( user_id_list != null && username_list != null )
            {
                throw new DuoException("user_id_list and username_list cannot both be populated in the same request");
            }
            else if( user_id_list != null )
            {
                requestParam.RequestData.Add("user_id_list", JsonConvert.SerializeObject(user_id_list));
            }
            else if( username_list != null )
            {
                requestParam.RequestData.Add("username_list", JsonConvert.SerializeObject(username_list));
            }
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync<IEnumerable<DuoUserResponseModel>>(
                HttpMethod.Get,
                "/admin/v1/users",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        } 
        
        /// <summary>
        /// Return a single user based on a search of either the username or email address of the user.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="username">
        /// Specify a user name (or username alias) to look up a single user.
        /// </param>
        /// <param name="email">
        /// Specify an email address to look up a single user.
        /// </param>
        /// <returns>User response model</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<DuoUserResponseModel>> GetUser(string? username = null, string? email = null)
        {
            // Request parameters
            var requestParam = new DuoParamRequestData
            {
                RequestData = new Dictionary<string, string>()
            };
            
            if( username != null && email != null )
            {
                throw new DuoException("username and email cannot both be populated in the same request");
            }
            else if( username != null )
            {
                requestParam.RequestData.Add("username", username);
            }
            else if( email != null )
            {
                requestParam.RequestData.Add("email", email);
            }
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync<IEnumerable<DuoUserResponseModel>>(
                HttpMethod.Get,
                "/admin/v1/users",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return new DuoResponseModel<DuoUserResponseModel>
            {
                ErrorMessageDetail = apiResponse.ResponseData.ErrorMessageDetail,
                Response = apiResponse.ResponseData.Response?.FirstOrDefault(),
                ResponseMetadata = apiResponse.ResponseData.ResponseMetadata,
                ErrorMessage = apiResponse.ResponseData.ErrorMessage,
                ErrorCode = apiResponse.ResponseData.ErrorCode,
                Status = apiResponse.ResponseData.Status
            };
        }
        
        /// <summary>
        /// Return a single user based on a search of either the username or email address of the user.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="userid">
        /// User ID
        /// </param>
        /// <returns>User response model</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<DuoUserResponseModel>> GetUserById(string userid)
        {
            // Validate userid
            if( string.IsNullOrEmpty(userid) )
            {
                throw new DuoException("Invalid userid in request");
            }
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync<DuoUserResponseModel>(
                HttpMethod.Get,
                $"/admin/v1/users/{userid}"
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        } 
        #endregion Retrieve Users
        
        #region Manipulate Users
        /// <summary>
        /// Create a new user
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model
        /// </param>
        /// <returns>Model of created user</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<DuoUserResponseModel>> CreateUser(DuoUserRequestModel user_model)
        {
            // Check model
            user_model = (DuoUserRequestModel)user_model.GetBaseClass(typeof(DuoUserRequestModel));
            if( string.IsNullOrEmpty(user_model.Username) )
            {
                throw new DuoException("username is required in DuoUserRequestModel for CreateUser");
            }
            
            // Make API request
            var requestParam = new DuoJsonRequestDataObject(user_model);
            var apiResponse = await duo_api.APICallAsync<DuoUserResponseModel>(
                HttpMethod.Post,
                "/admin/v1/users",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        
        /// <summary>
        /// Create multiple users
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// Array of user models
        /// </param>
        /// <returns>Array of Models of created users</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoUserResponseModel>>> CreateUser(IEnumerable<DuoUserRequestModel> user_model)
        {
            return await CreateUser(user_model.ToArray());
        }
        
        /// <summary>
        /// Create multiple users
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// Array of user models
        /// </param>
        /// <returns>Array of Models of created users</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoUserResponseModel>>> CreateUser(DuoUserRequestModel[] user_model)
        {
            // Check model
            var processedModels = new List<DuoUserRequestModel>();
            foreach( var user in user_model )
            {
                if( string.IsNullOrEmpty(user.Username) )
                {
                    throw new DuoException("username is required in DuoUserRequestModel for CreateUser");
                }
                
                processedModels.Add((DuoUserRequestModel)user.GetBaseClass(typeof(DuoUserRequestModel)));
            }
            
            // Make API request
            var requestParam = new DuoJsonRequestDataObject(new{ users = JsonConvert.SerializeObject(processedModels) });
            var apiResponse = await duo_api.APICallAsync<IEnumerable<DuoUserResponseModel>>(
                HttpMethod.Post,
                "/admin/v1/users/bulk_create",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        
        /// <summary>
        /// Change the username, username aliases, full name, status, and/or notes section of the user with ID user_id.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model
        /// </param>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel> ModifyUser(DuoUserRequestModel user_model)
        {
            // Check userid
            user_model = (DuoUserRequestModel)user_model.GetBaseClass(typeof(DuoUserRequestModel));
            var userid = user_model.UserID;
            if( string.IsNullOrEmpty(userid) )
            {
                throw new DuoException("userid is required in DuoUserRequestModel for ModifyUser");
            }
            
            // Make API request
            user_model.UserID = null;
            var requestParam = new DuoJsonRequestDataObject(user_model);
            var apiResponse = await duo_api.APICallAsync<DuoUserResponseModel>(
                HttpMethod.Post,
                $"/admin/v1/users/{userid}",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        
        /// <summary>
        /// Delete the user with ID user_id from the system. The API will not delete phones associated only with that user right away; remove them immediately with Delete Phone.
        /// This method returns 200 if the phone was found or if no such phone exists.
        /// Requires "Grant write resource" API permission.
        ///
        /// Users deleted by the API do not get moved into the Trash view as "Pending Deletion" as they would if removed by directory sync,
        /// user deletion, or interactively from the Duo Admin Panel, and therefore are not available for restoration.
        /// Users deleted via the API are immediately and permanently removed from Duo.
        /// </summary>
        /// <param name="user_model">
        /// User model
        /// </param>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel> DeleteUser(DuoUserRequestModel user_model)
        {
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            return await DeleteUser(user_model.UserID);
        }
        
        /// <summary>
        /// Delete the user with ID user_id from the system. The API will not delete phones associated only with that user right away; remove them immediately with Delete Phone.
        /// This method returns 200 if the phone was found or if no such phone exists.
        /// Requires "Grant write resource" API permission.
        ///
        /// Users deleted by the API do not get moved into the Trash view as "Pending Deletion" as they would if removed by directory sync,
        /// user deletion, or interactively from the Duo Admin Panel, and therefore are not available for restoration.
        /// Users deleted via the API are immediately and permanently removed from Duo.
        /// </summary>
        /// <param name="user_id">
        /// User ID of the user to delete
        /// </param>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel> DeleteUser(string user_id)
        {
            // Check userid
            if( string.IsNullOrEmpty(user_id) )
            {
                throw new DuoException("userid is required in DuoUserRequestModel for ModifyUser");
            }
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync<DuoUserResponseModel>(
                HttpMethod.Delete,
                $"/admin/v1/users/{user_id}"
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        
        /// <summary>
        /// Enroll a user with user name username and email address email and send them an enrollment email that expires after valid_secs seconds.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model
        /// </param>
        /// <param name="valid_secs">
        /// The number of seconds the enrollment code should remain valid. Default: 2592000 (30 days).
        /// </param>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<string>> EnrollUser(DuoUserRequestModel user_model, int valid_secs = 2592000)
        {
            if( user_model.Username == null ) throw new DuoException("Invalid Username in request model");
            if( user_model.Email == null ) throw new DuoException("Invalid Email in request model");
            return await EnrollUser(user_model.Username, user_model.Email, valid_secs);
        }
        
        /// <summary>
        /// Enroll a user with user name username and email address email and send them an enrollment email that expires after valid_secs seconds.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="username">
        /// The user name (or username alias) of the user to enroll.
        /// </param>
        /// <param name="email">
        /// The email address of this user.
        /// </param>
        /// <param name="valid_secs">
        /// The number of seconds the enrollment code should remain valid. Default: 2592000 (30 days).
        /// </param>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<string>> EnrollUser(string username, string email, int valid_secs = 2592000)
        {
            // Check username
            if( string.IsNullOrEmpty(username) || string.IsNullOrEmpty(email) )
            {
                throw new DuoException("username and email are required for EnrollUser");
            }
            
            // Make API request
            var requestParam = new DuoJsonRequestDataObject(new{ username, email, valid_secs = $"{valid_secs}" });
            var apiResponse = await duo_api.APICallAsync<string>(
                HttpMethod.Post,
                $"/admin/v1/users/enroll",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        #endregion Manipulate Users
        
        #region Bypass Codes
        /// <summary>
        /// Clear all existing bypass codes for the user with ID user_id and return a list of count newly generated bypass codes, or specify codes that expire after valid_secs seconds, or reuse_count uses.
        /// To preserve existing bypass codes instead of clearing them the request must specify preserve_existing=true.
        /// </summary>
        /// <param name="user_model">
        /// User model to create bypass codes for
        /// </param>
        /// <param name="count">
        /// Number of new bypass codes to create. At most 10 codes (the default) can be created at a time.
        /// Codes will be generated randomly.
        /// </param>
        /// <param name="codes">
        /// Array of codes to use. Mutually exclusive with count.
        /// </param>
        /// <param name="preserve_existing">
        /// Preserves existing bypass codes while creating new ones. Either true or false; effectively false if not specified.
        /// If true and the request would result the target user reaching the limit of 100 codes per user, or if codes is used and specifies a bypass code that already exists for the target user,
        /// then an error is returned and no bypass codes are created for nor cleared from the user.
        /// </param>
        /// <param name="reuse_count">
        /// The number of times generated bypass codes can be used. If 0, the codes will have an infinite reuse_count.
        /// Default: 1.
        /// </param>
        /// <param name="valid_secs">
        /// The number of seconds for which generated bypass codes remain valid.
        /// If 0 (the default) the codes will never expire.
        /// </param>
        /// <returns>Array of bypass codes</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<string>>> CreateUserBypassCodes(DuoUserRequestModel user_model, int count = 10, string[]? codes = null, bool preserve_existing = false, int reuse_count = 1, int valid_secs = 0)
        {
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            return await CreateUserBypassCodes(user_model.UserID, count, codes, preserve_existing, reuse_count, valid_secs);
        }
        
        /// <summary>
        /// Clear all existing bypass codes for the user with ID user_id and return a list of count newly generated bypass codes, or specify codes that expire after valid_secs seconds, or reuse_count uses.
        /// To preserve existing bypass codes instead of clearing them the request must specify preserve_existing=true.
        /// </summary>
        /// <param name="user_id">
        /// User ID to create bypass codes for
        /// </param>
        /// <param name="count">
        /// Number of new bypass codes to create. At most 10 codes (the default) can be created at a time.
        /// Codes will be generated randomly.
        /// </param>
        /// <param name="codes">
        /// Array of codes to use. Mutually exclusive with count.
        /// </param>
        /// <param name="preserve_existing">
        /// Preserves existing bypass codes while creating new ones. Either true or false; effectively false if not specified.
        /// If true and the request would result the target user reaching the limit of 100 codes per user, or if codes is used and specifies a bypass code that already exists for the target user,
        /// then an error is returned and no bypass codes are created for nor cleared from the user.
        /// </param>
        /// <param name="reuse_count">
        /// The number of times generated bypass codes can be used. If 0, the codes will have an infinite reuse_count.
        /// Default: 1.
        /// </param>
        /// <param name="valid_secs">
        /// The number of seconds for which generated bypass codes remain valid.
        /// If 0 (the default) the codes will never expire.
        /// </param>
        /// <returns>Array of bypass codes</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<string>>> CreateUserBypassCodes(string user_id, int count = 10, string[]? codes = null, bool preserve_existing = false, int reuse_count = 1, int valid_secs = 0)
        {
            // Check userid
            if( string.IsNullOrEmpty(user_id) )
            {
                throw new DuoException("userid is required for CreateUserBypassCodes");
            }
            
            // Make API request
            var requestParam = new DuoJsonRequestDataObject(new
            {
                preserve_existing = preserve_existing ? "true" : "false",
                codes = codes != null ? string.Join(",", codes) : null,
                reuse_count = $"{reuse_count}",
                valid_secs = $"{valid_secs}",
                count = $"{count}", 
            });
            var apiResponse = await duo_api.APICallAsync<IEnumerable<string>>(
                HttpMethod.Post,
                $"/admin/v1/users/{user_id}/bypass_codes",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        
        /// <summary>
        /// Returns a paged list of bypass code metadata associated with the user with ID user_id.
        /// To fetch all results, call repeatedly with the offset parameter as long as the result metadata has a next_offset value. D
        /// Does not return the actual bypass codes.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model to retrieve bypass codes for
        /// </param>
        /// <param name="limit">
        /// The maximum number of records returned.
        /// Default: 100; Max: 300
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User bypass code model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoBypassCodeResponseModel>>> GetUserBypassCodes(DuoUserRequestModel user_model, int limit = 100, int offset = 0)
        {
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            return await GetUserBypassCodes(user_model.UserID, limit, offset);
        }
        
        /// <summary>
        /// Returns a paged list of bypass code metadata associated with the user with ID user_id.
        /// To fetch all results, call repeatedly with the offset parameter as long as the result metadata has a next_offset value. D
        /// Does not return the actual bypass codes.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="user_id">
        /// User ID to retrieve bypass codes for
        /// </param>
        /// <param name="limit">
        /// The maximum number of records returned.
        /// Default: 100; Max: 300
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User bypass code model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoBypassCodeResponseModel>>> GetUserBypassCodes(string user_id, int limit = 100, int offset = 0)
        {
            // Check userid
            if( string.IsNullOrEmpty(user_id) )
            {
                throw new DuoException("userid is required for CreateUserBypassCodes");
            }
            
            // Check paging bounds
            if( limit is > 300 or < 1 ) limit = 100;
            if( offset < 1 ) offset = 0;
            
            // Request parameters
            var requestParam = new DuoParamRequestData
            {
                RequestData = new Dictionary<string, string>
                {
                    { "offset", $"{offset}" },
                    { "limit", $"{limit}" }
                }
            };
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync<IEnumerable<DuoBypassCodeResponseModel>>(
                HttpMethod.Get,
                $"/admin/v1/users/{user_id}/bypass_codes",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        #endregion Bypass Codes
        
        #region User Groups
        /// <summary>
        /// Returns a paged list of groups associated with the user with ID user_id.
        /// To fetch all results, call repeatedly with the offset parameter as long as the result metadata has a next_offset value.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User Model to retrieve groups for
        /// </param>
        /// <param name="limit">
        /// The maximum number of records returned.
        /// Default: 100; Max: 500
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoGroupResponseModel>>> GetUserGroups(DuoUserRequestModel user_model, int limit = 100, int offset = 0)
        {
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            return await GetUserGroups(user_model.UserID, limit, offset);
        }
        
        /// <summary>
        /// Returns a paged list of groups associated with the user with ID user_id.
        /// To fetch all results, call repeatedly with the offset parameter as long as the result metadata has a next_offset value.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="user_id">
        /// User ID to retrieve groups for
        /// </param>
        /// <param name="limit">
        /// The maximum number of records returned.
        /// Default: 100; Max: 500
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoGroupResponseModel>>> GetUserGroups(string user_id, int limit = 100, int offset = 0)
        {
            // Check userid
            if( string.IsNullOrEmpty(user_id) )
            {
                throw new DuoException("user_id is required for GetUserGroups");
            }
            
            // Check paging bounds
            if( limit is > 500 or < 1 ) limit = 100;
            if( offset < 1 ) offset = 0;
            
            // Request parameters
            var requestParam = new DuoParamRequestData
            {
                RequestData = new Dictionary<string, string>
                {
                    { "offset", $"{offset}" },
                    { "limit", $"{limit}" }
                }
            };
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync<IEnumerable<DuoGroupResponseModel>>(
                HttpMethod.Get,
                $"/admin/v1/users/{user_id}/groups",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        
        /// <summary>
        /// Associate a group with ID group_id with the user with ID user_id.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model to associate with the group
        /// </param>
        /// <param name="group_model">
        /// Group model to associate with the user
        /// </param>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<DuoResponseModel> AssociateGroupWithUser(DuoUserRequestModel user_model, DuoGroupRequestModel group_model)
        {
            if( group_model.GroupID == null ) throw new DuoException("Invalid GroupID in request model");
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            return await AssociateGroupWithUser(user_model.UserID, group_model.GroupID);
        }
        
        /// <summary>
        /// Associate a group with ID group_id with the user with ID user_id.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_id">
        /// User id to associate with the group
        /// </param>
        /// <param name="group_id">
        /// Group id to associate with the user
        /// </param>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<DuoResponseModel> AssociateGroupWithUser(string user_id, string group_id)
        {
            // Check userid
            if( string.IsNullOrEmpty(user_id) )
            {
                throw new DuoException("user_id is required for AssociateGroupWithUser");
            }
            if( string.IsNullOrEmpty(group_id) )
            {
                throw new DuoException("group_id is required for AssociateGroupWithUser");
            }
            
            // Make API request
            var requestParam = new DuoJsonRequestDataObject(new
            {
                group_id
            });
            var apiResponse = await duo_api.APICallAsync(
                HttpMethod.Post,
                $"/admin/v1/users/{user_id}/groups",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        
        /// <summary>
        /// Disassociate a group from the user with ID user_id.
        /// This method will return 200 if the group was found or if no such group exists.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model to disassociate from the group
        /// </param>
        /// <param name="group_model">
        /// Group model to disassociate from the user
        /// </param>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<DuoResponseModel> DisassociateGroupFromUser(DuoUserRequestModel user_model, DuoGroupRequestModel group_model)
        {
            if( group_model.GroupID == null ) throw new DuoException("Invalid GroupID in request model");
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            return await DisassociateGroupFromUser(user_model.UserID, group_model.GroupID);
        }
        
        /// <summary>
        /// Disassociate a group from the user with ID user_id.
        /// This method will return 200 if the group was found or if no such group exists.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_id">
        /// User id to disassociate from the group
        /// </param>
        /// <param name="group_id">
        /// Group id to disassociate from the user
        /// </param>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<DuoResponseModel> DisassociateGroupFromUser(string user_id, string group_id)
        {
            // Check userid
            if( string.IsNullOrEmpty(user_id) )
            {
                throw new DuoException("user_id is required for AssociateGroupWithUser");
            }
            if( string.IsNullOrEmpty(group_id) )
            {
                throw new DuoException("group_id is required for AssociateGroupWithUser");
            }
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync(
                HttpMethod.Delete,
                $"/admin/v1/users/{user_id}/groups/{group_id}"
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        #endregion User Groups
        
        #region Phones
        /// <summary>
        /// Returns a paged list of phones associated with the user with ID user_id.
        /// To fetch all results, call repeatedly with the offset parameter as long as the result metadata has a next_offset value.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model to retrieve phones for
        /// </param>
        /// <param name="limit">
        /// The maximum number of records returned.
        /// Default: 100; Max: 500
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoPhoneResponseModel>>> GetUserPhones(DuoUserRequestModel user_model, int limit = 100, int offset = 0)
        {
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            return await GetUserPhones(user_model.UserID, limit, offset);
        }
        
        /// <summary>
        /// Returns a paged list of phones associated with the user with ID user_id.
        /// To fetch all results, call repeatedly with the offset parameter as long as the result metadata has a next_offset value.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="user_id">
        /// User ID to retrieve phones for
        /// </param>
        /// <param name="limit">
        /// The maximum number of records returned.
        /// Default: 100; Max: 500
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoPhoneResponseModel>>> GetUserPhones(string user_id, int limit = 100, int offset = 0)
        {
            // Check userid
            if( string.IsNullOrEmpty(user_id) )
            {
                throw new DuoException("user_id is required for GetUserPhones");
            }
            
            // Check paging bounds
            if( limit is > 500 or < 1 ) limit = 100;
            if( offset < 1 ) offset = 0;
            
            // Request parameters
            var requestParam = new DuoParamRequestData
            {
                RequestData = new Dictionary<string, string>
                {
                    { "offset", $"{offset}" },
                    { "limit", $"{limit}" }
                }
            };
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync<IEnumerable<DuoPhoneResponseModel>>(
                HttpMethod.Get,
                $"/admin/v1/users/{user_id}/phones",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        
        /// <summary>
        /// Associate a phone with the user with ID user_id.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model to associate with phone
        /// </param>
        /// <param name="phone_model">
        /// Phone model to associate with user
        /// </param>
        public async Task<DuoResponseModel> AssociatePhoneWithUser(DuoUserRequestModel user_model, DuoPhoneRequestModel phone_model)
        {
            if( phone_model.PhoneID == null ) throw new DuoException("Invalid PhoneID in request model");
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            return await AssociatePhoneWithUser(user_model.UserID, phone_model.PhoneID);
        }
        
        /// <summary>
        /// Associate a phone with the user with ID user_id.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_id">
        /// User id to associate with phone
        /// </param>
        /// <param name="phone_id">
        /// Phone id to associate with user
        /// </param>
        public async Task<DuoResponseModel> AssociatePhoneWithUser(string user_id, string phone_id)
        {
            // Check userid
            if( string.IsNullOrEmpty(user_id) )
            {
                throw new DuoException("user_id is required for AssociatePhoneWithUser");
            }
            if( string.IsNullOrEmpty(phone_id) )
            {
                throw new DuoException("phone_id is required for AssociatePhoneWithUser");
            }
            
            // Make API request
            var requestParam = new DuoJsonRequestDataObject(new
            {
                phone_id
            });
            var apiResponse = await duo_api.APICallAsync(
                HttpMethod.Post,
                $"/admin/v1/users/{user_id}/phones",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        
        /// <summary>
        /// Disassociate a phone from the user with ID user_id.
        /// The API will not automatically delete the phone after removing the last user association; remove it permanently with Delete Phone.
        /// This method returns 200 if the phone was found or if no such phone exists.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model to disassociate from phone
        /// </param>
        /// <param name="phone_model">
        /// Phone model to disassociate from user
        /// </param>
        public async Task<DuoResponseModel> DisassociatePhoneFromUser(DuoUserRequestModel user_model, DuoPhoneRequestModel phone_model)
        {
            if( phone_model.PhoneID == null ) throw new DuoException("Invalid PhoneID in request model");
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            return await DisassociatePhoneFromUser(user_model.UserID, phone_model.PhoneID);
        }
        
        /// <summary>
        /// Disassociate a phone from the user with ID user_id.
        /// The API will not automatically delete the phone after removing the last user association; remove it permanently with Delete Phone.
        /// This method returns 200 if the phone was found or if no such phone exists.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_id">
        /// User id to disassociate from phone
        /// </param>
        /// <param name="phone_id">
        /// Phone id to disassociate from user
        /// </param>
        public async Task<DuoResponseModel> DisassociatePhoneFromUser(string user_id, string phone_id)
        {
            // Check userid
            if( string.IsNullOrEmpty(user_id) )
            {
                throw new DuoException("user_id is required for AssociatePhoneWithUser");
            }
            if( string.IsNullOrEmpty(phone_id) )
            {
                throw new DuoException("phone_id is required for AssociatePhoneWithUser");
            }
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync(
                HttpMethod.Delete,
                $"/admin/v1/users/{user_id}/phones/{phone_id}"
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        #endregion Phones
        
        #region Hardware Tokens
        /// <summary>
        /// Returns a paged list of OTP hardware tokens associated with the user with ID user_id.
        /// To fetch all results, call repeatedly with the offset parameter as long as the result metadata has a next_offset value.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model to retrieve tokens for
        /// </param>
        /// <param name="limit">
        /// The maximum number of records returned.
        /// Default: 100; Max: 500
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoHardwareTokenResponseModel>>> GetUserHardwareTokens(DuoUserRequestModel user_model, int limit = 100, int offset = 0)
        {
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            return await GetUserHardwareTokens(user_model.UserID, limit, offset);
        }
        
        /// <summary>
        /// Returns a paged list of OTP hardware tokens associated with the user with ID user_id.
        /// To fetch all results, call repeatedly with the offset parameter as long as the result metadata has a next_offset value.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="user_id">
        /// User ID to retrieve tokens for
        /// </param>
        /// <param name="limit">
        /// The maximum number of records returned.
        /// Default: 100; Max: 500
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoHardwareTokenResponseModel>>> GetUserHardwareTokens(string user_id, int limit = 100, int offset = 0)
        {
            // Check userid
            if( string.IsNullOrEmpty(user_id) )
            {
                throw new DuoException("user_id is required for GetUserPhones");
            }
            
            // Check paging bounds
            if( limit is > 500 or < 1 ) limit = 100;
            if( offset < 1 ) offset = 0;
            
            // Request parameters
            var requestParam = new DuoParamRequestData
            {
                RequestData = new Dictionary<string, string>
                {
                    { "offset", $"{offset}" },
                    { "limit", $"{limit}" }
                }
            };
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync<IEnumerable<DuoHardwareTokenResponseModel>>(
                HttpMethod.Get,
                $"/admin/v1/users/{user_id}/tokens",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        
        /// <summary>
        /// Associate a hardware token with the user with ID user_id.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model to associate with token
        /// </param>
        /// <param name="token_model">
        /// Token model to associate with user
        /// </param>
        public async Task<DuoResponseModel> AssociateHardwareTokenWithUser(DuoUserRequestModel user_model, DuoHardwareTokenRequestModel token_model)
        {
            if( token_model.TokenID == null ) throw new DuoException("Invalid TokenID in request model");
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            return await AssociateHardwareTokenWithUser(user_model.UserID, token_model.TokenID);
        }
        
        /// <summary>
        /// Associate a hardware token with the user with ID user_id.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_id">
        /// User id to associate with token
        /// </param>
        /// <param name="token_id">
        /// Token id to associate with user
        /// </param>
        public async Task<DuoResponseModel> AssociateHardwareTokenWithUser(string user_id, string token_id)
        {
            // Check userid
            if( string.IsNullOrEmpty(user_id) )
            {
                throw new DuoException("user_id is required for AssociateHardwareTokenWithUser");
            }
            if( string.IsNullOrEmpty(token_id) )
            {
                throw new DuoException("token_id is required for AssociateHardwareTokenWithUser");
            }
            
            // Make API request
            var requestParam = new DuoJsonRequestDataObject(new
            {
                token_id
            });
            var apiResponse = await duo_api.APICallAsync(
                HttpMethod.Post,
                $"/admin/v1/users/{user_id}/tokens",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        
        /// <summary>
        /// Disassociate a hardware token from the user with ID user_id.
        /// This method will return 200 if the hardware token was found or if no such hardware token exists.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model to disassociate from token
        /// </param>
        /// <param name="token_model">
        /// Token model to disassociate from user
        /// </param>
        public async Task<DuoResponseModel> DisassociateHardwareTokenWithUser(DuoUserRequestModel user_model, DuoHardwareTokenRequestModel token_model)
        {
            if( token_model.TokenID == null ) throw new DuoException("Invalid TokenID in request model");
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            return await DisassociatePhoneFromUser(user_model.UserID, token_model.TokenID);
        }
        
        /// <summary>
        /// Disassociate a hardware token from the user with ID user_id.
        /// This method will return 200 if the hardware token was found or if no such hardware token exists.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_id">
        /// User id to disassociate from token
        /// </param>
        /// <param name="token_id">
        /// Token id to disassociate from user
        /// </param>
        public async Task<DuoResponseModel> DisassociateHardwareTokenWithUser(string user_id, string token_id)
        {
            // Check userid
            if( string.IsNullOrEmpty(user_id) )
            {
                throw new DuoException("user_id is required for DisassociateHardwareTokenWithUser");
            }
            if( string.IsNullOrEmpty(token_id) )
            {
                throw new DuoException("phone_id is required for DisassociateHardwareTokenWithUser");
            }
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync(
                HttpMethod.Delete,
                $"/admin/v1/users/{user_id}/tokens/{token_id}"
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        #endregion Hardware Tokens
        
        #region Other Tokens
        /// <summary>
        /// Returns a list of WebAuthn credentials associated with the user with ID user_id.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model to retrieve tokens for
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoWebAuthNResponseModel>>> GetUserWebAuthNTokens(DuoUserRequestModel user_model)
        {
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            return await GetUserWebAuthNTokens(user_model.UserID);
        }
        
        /// <summary>
        /// Returns a list of WebAuthn credentials associated with the user with ID user_id.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="user_id">
        /// User id to retrieve tokens for
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoWebAuthNResponseModel>>> GetUserWebAuthNTokens(string user_id)
        {
            // Check userid
            if( string.IsNullOrEmpty(user_id) )
            {
                throw new DuoException("user_id is required for GetUserPhones");
            }
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync<IEnumerable<DuoWebAuthNResponseModel>>(
                HttpMethod.Get,
                $"/admin/v1/users/{user_id}/webauthncredentials"
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }

        /// <summary>
        /// Returns a paged list of desktop authenticators associated with the user with ID user_id.
        /// To fetch all results, call repeatedly with the offset parameter as long as the result metadata has a next_offset value.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model to retrieve authenticators for
        /// </param>
        /// <param name="limit">
        /// The maximum number of records returned.
        /// Default: 100; Max: 500
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoDesktopAuthenticatorResponseModel>>> GetUserDesktopAuthenticators(DuoUserRequestModel user_model, int limit = 100, int offset = 0)
        {
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            return await GetUserDesktopAuthenticators(user_model.UserID, limit, offset);
        }
        
        /// <summary>
        /// Returns a paged list of desktop authenticators associated with the user with ID user_id.
        /// To fetch all results, call repeatedly with the offset parameter as long as the result metadata has a next_offset value.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="user_id">
        /// User model to retrieve authenticators for
        /// </param>
        /// <param name="limit">
        /// The maximum number of records returned.
        /// Default: 100; Max: 500
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoDesktopAuthenticatorResponseModel>>> GetUserDesktopAuthenticators(string user_id, int limit = 100, int offset = 0)
        {
            // Check userid
            if( string.IsNullOrEmpty(user_id) )
            {
                throw new DuoException("user_id is required for GetUserPhones");
            }
            
            // Check paging bounds
            if( limit is > 500 or < 1 ) limit = 100;
            if( offset < 1 ) offset = 0;
            
            // Request parameters
            var requestParam = new DuoParamRequestData
            {
                RequestData = new Dictionary<string, string>
                {
                    { "offset", $"{offset}" },
                    { "limit", $"{limit}" }
                }
            };
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync<IEnumerable<DuoDesktopAuthenticatorResponseModel>>(
                HttpMethod.Get,
                $"/admin/v1/users/{user_id}/desktopauthenticators",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        #endregion Other Tokens
        
        #region Other Methods
        /// <summary>
        /// Initiate a sync to create, update, or mark for deletion the user specified by username against the directory specified by the directory_key.
        /// The directory_key for a directory can be found by navigating to Users → Directory Sync in the Duo Admin Panel,
        /// and then clicking on the configured directory. Learn more about syncing individual users from Active Directory, OpenLDAP, or Entra ID.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model of the user to sync
        /// </param>
        /// <param name="directory_key">
        /// Key retrieved from the Web UI of the directory to sync
        /// </param>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel> SyncUserFromDirectory(DuoUserRequestModel user_model, string directory_key)
        {
            if( user_model.Username == null ) throw new DuoException("Invalid Username in request model");
            return await SyncUserFromDirectory(user_model.Username, directory_key);
        }
        
        /// <summary>
        /// Initiate a sync to create, update, or mark for deletion the user specified by username against the directory specified by the directory_key.
        /// The directory_key for a directory can be found by navigating to Users → Directory Sync in the Duo Admin Panel,
        /// and then clicking on the configured directory. Learn more about syncing individual users from Active Directory, OpenLDAP, or Entra ID.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="username">
        /// Username of the user to sync
        /// </param>
        /// <param name="directory_key">
        /// Key retrieved from the Web UI of the directory to sync
        /// </param>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel> SyncUserFromDirectory(string username, string directory_key)
        {
            // Check userid
            if( string.IsNullOrEmpty(username) )
            {
                throw new DuoException("username is required for SyncUserFromDirectory");
            }
            if( string.IsNullOrEmpty(directory_key) )
            {
                throw new DuoException("directory_key is required for SyncUserFromDirectory");
            }
            
            // Request parameters
            var requestParam = new DuoJsonRequestDataObject(new
            {
                username
            });
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync<IEnumerable<DuoDesktopAuthenticatorResponseModel>>(
                HttpMethod.Post,
                $"/admin/v1/users/directorysync/{directory_key}/syncuser",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        
        /// <summary>
        /// Sends a verification Duo Push to the user with ID user_id.
        /// Verification pushes can also be sent from the Duo Admin Panel.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model of the user to send the notification to
        /// </param>
        /// <param name="phone_model">
        /// Phone model of the device to send the notification to
        /// </param>
        /// <returns>Push ID which can be used to validate the message was accepted using VerifyPushResponse</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<DuoVerificationPushResponseModel>> SendVerificationPush(DuoUserRequestModel user_model, DuoPhoneRequestModel phone_model)
        {
            if( phone_model.PhoneID == null ) throw new DuoException("Invalid PhoneID in request model");
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            return await SendVerificationPush(user_model.UserID, phone_model.PhoneID);
        }
        
        /// <summary>
        /// Sends a verification Duo Push to the user with ID user_id.
        /// Verification pushes can also be sent from the Duo Admin Panel.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_id">
        /// User id of the user to send the notification to
        /// </param>
        /// <param name="phone_id">
        /// Phone id of the device to send the notification to
        /// </param>
        /// <returns>Push ID which can be used to validate the message was accepted using VerifyPushResponse</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<DuoVerificationPushResponseModel>> SendVerificationPush(string user_id, string phone_id)
        {
            // Check userid
            if( string.IsNullOrEmpty(user_id) )
            {
                throw new DuoException("user_id is required for SendVerificationPush");
            }
            if( string.IsNullOrEmpty(phone_id) )
            {
                throw new DuoException("phone_id is required for SendVerificationPush");
            }
            
            // Request parameters
            var requestParam = new DuoJsonRequestDataObject(new
            {
                phone_id
            });
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync<DuoVerificationPushResponseModel>(
                HttpMethod.Post,
                $"/admin/v1/users/{user_id}/send_verification_push",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        
        /// <summary>
        /// Retrieves the verification push result for the user with ID user_id. Push response information will be available for 120 seconds after the push was sent,
        /// after which this endpoint will return a 404. If no success or failure response was returned by this endpoint during these 120 seconds,
        /// it can be assumed that the push has timed out.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model of the user to send the notification to
        /// </param>
        /// <param name="push_id">
        /// The ID of the Duo Push sent.
        /// </param>
        /// <returns>Push response status</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<DuoVerificationValidationResponseModel>> VerifyPushResponse(DuoUserRequestModel user_model, string push_id)
        {
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            return await VerifyPushResponse(user_model.UserID, push_id);
        }
        
        /// <summary>
        /// Retrieves the verification push result for the user with ID user_id. Push response information will be available for 120 seconds after the push was sent,
        /// after which this endpoint will return a 404. If no success or failure response was returned by this endpoint during these 120 seconds,
        /// it can be assumed that the push has timed out.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="user_id">
        /// User model of the user to send the notification to
        /// </param>
        /// <param name="push_id">
        /// The ID of the Duo Push sent.
        /// </param>
        /// <returns>Push response status</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<DuoVerificationValidationResponseModel>> VerifyPushResponse(string user_id, string push_id)
        {
            // Check userid
            if( string.IsNullOrEmpty(user_id) )
            {
                throw new DuoException("user_id is required for VerifyPushResponse");
            }
            if( string.IsNullOrEmpty(push_id) )
            {
                throw new DuoException("push_id is required for VerifyPushResponse");
            }
            
            // Request parameters
            var requestParam = new DuoJsonRequestDataObject(new
            {
                push_id
            });
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync<DuoVerificationValidationResponseModel>(
                HttpMethod.Get,
                $"/admin/v1/users/{user_id}/verification_push_response",
                requestParam
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        #endregion Other Methods
    }
}