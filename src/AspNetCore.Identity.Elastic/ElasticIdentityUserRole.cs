using System;
using Nest;

namespace AspNetCore.Identity.Elastic
{
    public class ElasticIdentityUserRole : IEquatable<ElasticIdentityUserRole>, IEquatable<string>
    {
        public ElasticIdentityUserRole(string roleId)
        {
            RoleId = roleId;
        }

        [Keyword]
        public string RoleId { get; set; }

        public bool Equals(ElasticIdentityUserRole other)
        {
            return other.Equals(RoleId);
        }

        public bool Equals(string other)
        {
            return other.Equals(RoleId);
        }
    }
}