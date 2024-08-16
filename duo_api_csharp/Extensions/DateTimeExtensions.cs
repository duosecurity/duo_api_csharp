using System.Globalization;

namespace duo_api_csharp.Extensions
{
    internal static class DateTimeExtensions
    {
        /// <summary>
        /// Custom RFC822 implementation for Duo
        /// </summary>
        /// <param name="date">DateTime object</param>
        /// <returns>Date formatted string</returns>
        internal static string DateToRFC822(this DateTime date)
        {
            // Can't use the "zzzz" format because it adds a ":"
            // between the offset's hours and minutes.
            var date_string = date.ToString("ddd, dd MMM yyyy HH:mm:ss", CultureInfo.InvariantCulture);
            var offset = 0;
            
            // set offset if input date is not UTC time.
            if( date.Kind != DateTimeKind.Utc )
            {
                offset = TimeZoneInfo.Local.GetUtcOffset(date).Hours;
            }
            
            string zone;
            // + or -, then 0-pad, then offset, then more 0-padding.
            if( offset < 0 )
            {
                offset *= -1;
                zone = "-";
            }
            else
            {
                zone = "+";
            }
            
            zone += offset.ToString(CultureInfo.InvariantCulture).PadLeft(2, '0');
            date_string += " " + zone.PadRight(5, '0');
            return date_string;
        }
    }
}