/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

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
        public AdminAPIv1_Groups Groups { get; init; } = new(duo_api);
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
        /// Default: 100; Max: 300
        /// </param>
        /// <param name="offset">
        /// The offset from 0 at which to start record retrieval.
        /// When used with "limit", the handler will return "limit" records starting at the n-th record, where n is the offset.
        /// Default: 0
        /// </param>
        /// <param name="group_id_list">
        /// A list of group ids used to fetch multiple groups by group_ids. You can provide up to 100 group_ids.
        /// </param>
        /// <returns>User response model(s)</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<IEnumerable<DuoGroupResponseModel>> GetGroups(int limit = 100, int offset = 0, string[]? group_id_list = null)
        {
            throw new NotImplementedException();
        } 
        #endregion Retrieve Groups
        
        #region Manipulate Groups
        /// <summary>
        /// Create a new group.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="group_model">
        /// Group model
        /// </param>
        /// <returns>Model of created group</returns>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task<DuoGroupResponseModel> CreateGroup(DuoGroupRequestModel group_model)
        {
            throw new NotImplementedException();
        }
        
        /// <summary>
        /// Update information about a group.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="group_model">
        /// Group model
        /// </param>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task UpdateGroup(DuoGroupRequestModel group_model)
        {
            throw new NotImplementedException();
        }
        
        /// <summary>
        /// Delete a group.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="group_model">
        /// Group model of the group to delete
        /// </param>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task DeleteGroup(DuoGroupRequestModel group_model)
        {
            if( group_model.GroupID == null ) throw new DuoException("Invalid GroupID in request model");
            await DeleteGroup(group_model.GroupID);
        }
        
        /// <summary>
        /// Delete a group.
        /// Requires "Grant write resource" API permission.
        /// </summary>
        /// <param name="group_id">
        /// Group ID of the group to delete
        /// </param>
        /// <exception cref="DuoException">API Exception</exception>
        public async Task DeleteGroup(string group_id)
        {
            throw new NotImplementedException();
        }
        #endregion Manipulate Groups
    }
}