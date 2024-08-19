/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */
 
namespace duo_api_csharp.Endpoints
{
    /// <summary>
    /// Duo Admin API - v2
    /// </summary>
    public sealed partial class AdminAPIv2
    {
        private readonly DuoAPI duo_api;
        internal AdminAPIv2(DuoAPI duo_api)
        {
            this.duo_api = duo_api;
        }
    }
}