/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

namespace duo_api_csharp.Classes
{
	internal class Epoch
	{
		private static readonly DateTime epochStart = new DateTime(1970, 1, 1, 0, 0, 0);
		
		public static DateTime? FromUnix(long? secondsSinceepoch)
		{
			if( secondsSinceepoch == null ) return null;
			return DateTime.SpecifyKind(epochStart.AddSeconds((long)secondsSinceepoch), DateTimeKind.Utc);
		}

		public static long? ToUnix(DateTime? dateTime)
		{
			if( dateTime == null ) return null;
			return (long)((DateTime)dateTime - epochStart).TotalSeconds;
		}

		public static long Now
	    {
			get
	        {
	            return (long)(DateTime.UtcNow - epochStart).TotalSeconds;
			}
		}
	}
}