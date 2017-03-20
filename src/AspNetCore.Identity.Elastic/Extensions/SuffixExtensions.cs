using Nest;

namespace AspNetCore.Identity.Elastic.Extensions
{
    internal static class SuffixExtensions
    {
        /// <summary>
        /// This extension method should only be used in expressions which are analysed by Nest.
        /// When analysed it will append "keyword" to the path separating it with a dot.
        /// </summary>
        internal static object Keyword(this object @object)
        {
            return @object.Suffix("keyword");
        }
    }
}
