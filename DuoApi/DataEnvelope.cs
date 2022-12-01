using System.ComponentModel.DataAnnotations;

namespace Duo
{

    /// <summary>
    /// 
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class DataEnvelope<T>
    {
        /// <summary>
        /// 
        /// </summary>
        [Required]
        public DuoApiResponseStatus stat { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public int? code { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public T response { get; set; }

        /// <summary>
        /// Upon error, basic error information
        /// </summary>
        public string message { get; set; }

        /// <summary>
        /// Upon error, detailed error information
        /// </summary>
        public string message_detail { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public PagingInfo metadata { get; set; }
    }
}
