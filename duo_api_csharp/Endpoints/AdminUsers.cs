/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

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
        public AdminAPIv1_Users Users { get; init; } = new(duo_api);
    }
    
    public sealed class AdminAPIv1_Users
    {
        #region Internal constructor
        private readonly DuoAPI duo_api;
        internal AdminAPIv1_Users(DuoAPI duo_api)
        {
            this.duo_api = duo_api;
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
        public async Task<IEnumerable<DuoUserResponseModel>> GetUsers(int limit = 100, int offset = 0, string[]? user_id_list = null, string[]? username_list = null)
        {
            throw new NotImplementedException();
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
        public async Task<DuoUserResponseModel> GetUser(string? username = null, string? email = null)
        {
            throw new NotImplementedException();
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
        public async Task<DuoUserResponseModel> GetUserById(string userid)
        {
            throw new NotImplementedException();
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
        public async Task<DuoUserResponseModel> CreateUser(DuoUserRequestModel user_model)
        {
            throw new NotImplementedException();
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
        public async Task<IEnumerable<DuoUserResponseModel>> CreateUser(DuoUserRequestModel[] user_model)
        {
            throw new NotImplementedException();
        }
        
        /// <summary>
        /// Change the username, username aliases, full name, status, and/or notes section of the user with ID user_id.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_model">
        /// User model
        /// </param>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task UpdateUser(DuoUserRequestModel user_model)
        {
            throw new NotImplementedException();
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
        public async Task DeleteUser(DuoUserRequestModel user_model)
        {
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            await DeleteUser(user_model.UserID);
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
        public async Task DeleteUser(string user_id)
        {
            throw new NotImplementedException();
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
        public async Task EnrollUser(DuoUserRequestModel user_model, int valid_secs = 2592000)
        {
            if( user_model.Username == null ) throw new DuoException("Invalid Username in request model");
            if( user_model.Email == null ) throw new DuoException("Invalid Email in request model");
            await EnrollUser(user_model.Username, user_model.Email, valid_secs);
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
        public async Task EnrollUser(string username, string email, int valid_secs = 2592000)
        {
            throw new NotImplementedException();
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
        public async Task<IEnumerable<string>> CreateUserBypassCodes(DuoUserRequestModel user_model, int count = 10, string[]? codes = null, bool preserve_existing = false, int reuse_count = 1, int valid_secs = 0)
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
        public async Task<IEnumerable<string>> CreateUserBypassCodes(string user_id, int count = 10, string[]? codes = null, bool preserve_existing = false, int reuse_count = 1, int valid_secs = 0)
        {
            throw new NotImplementedException();
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
        public async Task<IEnumerable<DuoBypassCodeModel>> GetUserBypassCodes(DuoUserRequestModel user_model, int limit = 100, int offset = 0)
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
        public async Task<IEnumerable<DuoBypassCodeModel>> GetUserBypassCodes(string user_id, int limit = 100, int offset = 0)
        {
            throw new NotImplementedException();
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
        /// Default: 100; Max: 300
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<IEnumerable<DuoGroupResponseModel>> GetUserGroups(DuoUserRequestModel user_model, int limit = 100, int offset = 0)
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
        /// Default: 100; Max: 300
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<IEnumerable<DuoGroupResponseModel>> GetUserGroups(string user_id, int limit = 100, int offset = 0)
        {
            throw new NotImplementedException();
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
        public async Task AssociateGroupWithUser(DuoUserRequestModel user_model, DuoGroupRequestModel group_model)
        {
            if( group_model.GroupID == null ) throw new DuoException("Invalid GroupID in request model");
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            await AssociateGroupWithUser(user_model.UserID, group_model.GroupID);
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
        public async Task AssociateGroupWithUser(string user_id, string group_id)
        {
            throw new NotImplementedException();
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
        public async Task DisassociateGroupFromUser(DuoUserRequestModel user_model, DuoGroupRequestModel group_model)
        {
            if( group_model.GroupID == null ) throw new DuoException("Invalid GroupID in request model");
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            await DisassociateGroupFromUser(user_model.UserID, group_model.GroupID);
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
        public async Task DisassociateGroupFromUser(string user_id, string group_id)
        {
            throw new NotImplementedException();
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
        /// Default: 100; Max: 300
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<IEnumerable<DuoPhoneResponseModel>> GetUserPhones(DuoUserRequestModel user_model, int limit = 100, int offset = 0)
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
        /// Default: 100; Max: 300
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<IEnumerable<DuoPhoneResponseModel>> GetUserPhones(string user_id, int limit = 100, int offset = 0)
        {
            throw new NotImplementedException();
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
        public async Task AssociatePhoneWithUser(DuoUserRequestModel user_model, DuoPhoneRequestModel phone_model)
        {
            if( phone_model.PhoneID == null ) throw new DuoException("Invalid PhoneID in request model");
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            await AssociatePhoneWithUser(user_model.UserID, phone_model.PhoneID);
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
        public async Task AssociatePhoneWithUser(string user_id, string phone_id)
        {
            throw new NotImplementedException();
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
        public async Task DisassociatePhoneFromUser(DuoUserRequestModel user_model, DuoPhoneRequestModel phone_model)
        {
            if( phone_model.PhoneID == null ) throw new DuoException("Invalid PhoneID in request model");
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            await DisassociatePhoneFromUser(user_model.UserID, phone_model.PhoneID);
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
        public async Task DisassociatePhoneFromUser(string user_id, string phone_id)
        {
            throw new NotImplementedException();
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
        /// Default: 100; Max: 300
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<IEnumerable<DuoPhoneResponseModel>> GetUserHardwareTokens(DuoUserRequestModel user_model, int limit = 100, int offset = 0)
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
        /// Default: 100; Max: 300
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<IEnumerable<DuoPhoneResponseModel>> GetUserHardwareTokens(string user_id, int limit = 100, int offset = 0)
        {
            throw new NotImplementedException();
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
        public async Task AssociateHardwareTokenWithUser(DuoUserRequestModel user_model, DuoHardwareTokenRequestModel token_model)
        {
            if( token_model.TokenID == null ) throw new DuoException("Invalid TokenID in request model");
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            await AssociateHardwareTokenWithUser(user_model.UserID, token_model.TokenID);
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
        public async Task AssociateHardwareTokenWithUser(string user_id, string token_id)
        {
            throw new NotImplementedException();
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
        public async Task DisassociateHardwareTokenWithUser(DuoUserRequestModel user_model, DuoHardwareTokenRequestModel token_model)
        {
            if( token_model.TokenID == null ) throw new DuoException("Invalid TokenID in request model");
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            await DisassociatePhoneFromUser(user_model.UserID, token_model.TokenID);
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
        public async Task DisassociateHardwareTokenWithUser(string user_id, string token_id)
        {
            throw new NotImplementedException();
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
        public async Task<IEnumerable<DuoWebAuthNRequestModel>> GetUserWebAuthNTokens(DuoUserRequestModel user_model)
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
        public async Task<IEnumerable<DuoWebAuthNRequestModel>> GetUserWebAuthNTokens(string user_id)
        {
            throw new NotImplementedException();
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
        /// Default: 100; Max: 300
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<IEnumerable<DuoDesktopAuthenticatorReponseModel>> GetUserDesktopAuthenticators(DuoUserRequestModel user_model, int limit = 100, int offset = 0)
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
        /// Default: 100; Max: 300
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <returns>User group model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<IEnumerable<DuoDesktopAuthenticatorReponseModel>> GetUserDesktopAuthenticators(string user_id, int limit = 100, int offset = 0)
        {
            throw new NotImplementedException();
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
        public async Task SyncUserFromDirectory(DuoUserRequestModel user_model, string directory_key)
        {
            if( user_model.UserID == null ) throw new DuoException("Invalid UserID in request model");
            await SyncUserFromDirectory(user_model.UserID, directory_key);
        }
        
        /// <summary>
        /// Initiate a sync to create, update, or mark for deletion the user specified by username against the directory specified by the directory_key.
        /// The directory_key for a directory can be found by navigating to Users → Directory Sync in the Duo Admin Panel,
        /// and then clicking on the configured directory. Learn more about syncing individual users from Active Directory, OpenLDAP, or Entra ID.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="user_id">
        /// User id of the user to sync
        /// </param>
        /// <param name="directory_key">
        /// Key retrieved from the Web UI of the directory to sync
        /// </param>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task SyncUserFromDirectory(string user_id, string directory_key)
        {
            throw new NotImplementedException();
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
        public async Task<string> SendVerificationPush(DuoUserRequestModel user_model, DuoPhoneRequestModel phone_model)
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
        public async Task<string> SendVerificationPush(string user_id, string phone_id)
        {
            throw new NotImplementedException();
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
        public async Task<DuoPushResponse> VerifyPushResponse(DuoUserRequestModel user_model, string push_id)
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
        public async Task<DuoPushResponse> VerifyPushResponse(string user_id, string push_id)
        {
            throw new NotImplementedException();
        }
        #endregion Other Methods
    }
}