namespace duo_api_csharp.Models.v1
{
    /// <summary>
    /// Result of a Duo API Push
    /// https://duo.com/docs/adminapi#retrieve-verification-push-response
    /// </summary>
    public enum DuoPushResponse
    {
        approve,
        deny,
        fraud,
        waiting
    }
}