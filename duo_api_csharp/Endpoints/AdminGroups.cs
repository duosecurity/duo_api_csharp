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
    public sealed partial class AdminAPIv1
    {
        /// <summary>
        /// Duo Admin API - Groups
        /// https://duo.com/docs/adminapi#groups
        /// </summary>
        public AdminAPIv1_Groups Groups { get; } = new(duo_api);
    }
    
    public sealed class AdminAPIv1_Groups
    {
        #region Internal constructor
        private readonly DuoAPI duo_api;
        internal AdminAPIv1_Groups(DuoAPI duo_api)
        {
            this.duo_api = duo_api;
        }
        #endregion Internal constructor
        
        #region Retrieve Groups
        /// <summary>
        /// Returns a paged list of groups. To fetch all results, call repeatedly with the offset parameter as long as the result metadata has a next_offset value.
        /// Requires "Grant read resource" API permission.
        /// </summary>
        /// <param name="limit">
        /// The maximum number of records returned.
        /// Default: 100; Max: 100
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <param name="group_id_list">
        /// A list of group ids used to fetch multiple groups by group_ids. You can provide up to 100 group_ids.
        /// </param>
        /// <returns>Group response model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoGroupResponseModel>>> GetGroups(int limit = 100, int offset = 0, string[]? group_id_list = null)
        {
            // Check paging bounds
            if( limit is > 100 or < 1 ) limit = 100;
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
            
            if( group_id_list != null )
            {
                requestParam.RequestData.Add("group_id_list", JsonConvert.SerializeObject(group_id_list));
            }
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync<IEnumerable<DuoGroupResponseModel>>(
                HttpMethod.Get,
                "/admin/v1/groups",
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
        #endregion Retrieve Groups
        
        #region Manipulate Groups
        /// <summary>
        /// Create a new group
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="group_model">
        /// Group model
        /// </param>
        /// <returns>Model of created group</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<DuoGroupResponseModel>> CreateGroup(DuoGroupRequestModel group_model)
        {
            // Check model
            group_model = (DuoGroupRequestModel)group_model.GetBaseClass(typeof(DuoGroupRequestModel));
            if( string.IsNullOrEmpty(group_model.Name) )
            {
                throw new DuoException("Name is required in DuoGroupRequestModel for CreateGroup");
            }
            
            // Make API request
            var requestParam = new DuoJsonRequestDataObject(group_model);
            var apiResponse = await duo_api.APICallAsync<DuoGroupResponseModel>(
                HttpMethod.Post,
                "/admin/v1/groups",
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
        /// Create multiple groups
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="group_model">
        /// Array of group models
        /// </param>
        /// <returns>Array of Models of created groups</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoGroupResponseModel>>> CreateGroup(IEnumerable<DuoGroupRequestModel> group_model)
        {
            return await CreateGroup(group_model.ToArray());
        }
        
        /// <summary>
        /// Create multiple groups
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="group_model">
        /// Array of group models
        /// </param>
        /// <returns>Array of Models of created groups</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel<IEnumerable<DuoGroupResponseModel>>> CreateGroup(DuoGroupRequestModel[] group_model)
        {
            // Check model
            var processedModels = new List<DuoGroupRequestModel>();
            foreach( var group in group_model )
            {
                if( string.IsNullOrEmpty(group.Name) )
                {
                    throw new DuoException("Name is required in DuoGroupRequestModel for CreateGroup");
                }
                
                processedModels.Add((DuoGroupRequestModel)group.GetBaseClass(typeof(DuoGroupRequestModel)));
            }
            
            // Make API request
            var requestParam = new DuoJsonRequestDataObject(new{ groups = JsonConvert.SerializeObject(processedModels) });
            var apiResponse = await duo_api.APICallAsync<IEnumerable<DuoGroupResponseModel>>(
                HttpMethod.Post,
                "/admin/v1/groups/bulk_create",
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
        /// Change the groupname, groupname aliases, full name, status, and/or notes section of the group with ID group_id.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="group_model">
        /// Group model
        /// </param>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel> ModifyGroup(DuoGroupRequestModel group_model)
        {
            // Check groupid
            group_model = (DuoGroupRequestModel)group_model.GetBaseClass(typeof(DuoGroupRequestModel));
            var groupid = group_model.GroupID;
            if( string.IsNullOrEmpty(groupid) )
            {
                throw new DuoException("groupid is required in DuoGroupRequestModel for ModifyGroup");
            }
            
            // Make API request
            group_model.GroupID = null;
            var requestParam = new DuoJsonRequestDataObject(group_model);
            var apiResponse = await duo_api.APICallAsync<DuoGroupResponseModel>(
                HttpMethod.Post,
                $"/admin/v1/groups/{groupid}",
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
        /// Delete the group with ID group_id from the system. The API will not delete phones associated only with that group right away; remove them immediately with Delete Phone.
        /// This method returns 200 if the phone was found or if no such phone exists.
        /// Requires "Grant write resource" API permission.
        ///
        /// Groups deleted by the API do not get moved into the Trash view as "Pending Deletion" as they would if removed by directory sync,
        /// group deletion, or interactively from the Duo Admin Panel, and therefore are not available for restoration.
        /// Groups deleted via the API are immediately and permanently removed from Duo.
        /// </summary>
        /// <param name="group_model">
        /// Group model
        /// </param>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel> DeleteGroup(DuoGroupRequestModel group_model)
        {
            if( group_model.GroupID == null ) throw new DuoException("Invalid GroupID in request model");
            return await DeleteGroup(group_model.GroupID);
        }
        
        /// <summary>
        /// Delete the group with ID group_id from the system. The API will not delete phones associated only with that group right away; remove them immediately with Delete Phone.
        /// This method returns 200 if the phone was found or if no such phone exists.
        /// Requires "Grant write resource" API permission.
        ///
        /// Groups deleted by the API do not get moved into the Trash view as "Pending Deletion" as they would if removed by directory sync,
        /// group deletion, or interactively from the Duo Admin Panel, and therefore are not available for restoration.
        /// Groups deleted via the API are immediately and permanently removed from Duo.
        /// </summary>
        /// <param name="group_id">
        /// Group ID of the group to delete
        /// </param>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoResponseModel> DeleteGroup(string group_id)
        {
            // Check groupid
            if( string.IsNullOrEmpty(group_id) )
            {
                throw new DuoException("groupid is required in DuoGroupRequestModel for ModifyGroup");
            }
            
            // Make API request
            var apiResponse = await duo_api.APICallAsync<DuoGroupResponseModel>(
                HttpMethod.Delete,
                $"/admin/v1/groups/{group_id}"
            );
            
            // Return data
            if( apiResponse.ResponseData == null )
            {
                // All requests should always deserialise into a response
                throw new DuoException("No response data from server", null, apiResponse.StatusCode, apiResponse.RequestSuccess);
            }
            
            return apiResponse.ResponseData;
        }
        #endregion Manipulate Groups
    }
}