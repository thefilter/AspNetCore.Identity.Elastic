using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.Elastic
{
    /// <summary>
    /// Implements <see cref="ILookupNormalizer"/> by converting keys to their lower cased invariant culture representation.
    /// </summary>
    public class LowerInvariantLookupNormalizer: ILookupNormalizer
    {
        public string Normalize(string key)
        {
            return key.ToLowerInvariant();
        }
    }
}
