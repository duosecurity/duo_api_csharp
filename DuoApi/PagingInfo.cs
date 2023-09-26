namespace Duo
{
    /// <summary>
    /// Information of dataset paging
    /// </summary>
    public struct PagingInfo
    {
        public int total_objects { get; set; }
        public int? next_offset { get; set; }
        public int prev_offset { get; set; }
    }
}
