using System;
using Nest;

namespace AspNetCore.Identity.Elastic
{
    public class ElasticIdentityUserRole : ElasticIdentityUserRole<string>
    {
    }

    public class ElasticIdentityUserRole<TKey> where TKey : IEquatable<TKey>
    {
        [Keyword]
        public TKey RoleId { get; set; }
    }
}