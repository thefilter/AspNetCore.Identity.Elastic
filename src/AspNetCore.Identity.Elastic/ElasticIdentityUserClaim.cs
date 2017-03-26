using System;
using System.Security.Claims;
using Nest;

namespace AspNetCore.Identity.Elastic
{
    public class ElasticIdentityUserClaim: IEquatable<ElasticIdentityUserClaim>, IEquatable<Claim>
    {
        public ElasticIdentityUserClaim()
        {
        }

        public ElasticIdentityUserClaim(Claim claim)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            Type = claim.Type;
            Value = claim.Value;
        }

        public ElasticIdentityUserClaim(string claimType, string claimValue)
        {
            if (claimType == null)
            {
                throw new ArgumentNullException(nameof(claimType));
            }
            if (claimValue == null)
            {
                throw new ArgumentNullException(nameof(claimValue));
            }
            Type = claimType;
            Value = claimValue;
        }

        [Keyword]
        public string Type { get; set; }

        [Keyword]
        public string Value { get; set; }

        public Claim ToClaim()
        {
            return new Claim(Type, Value);
        }

        public bool Equals(ElasticIdentityUserClaim other)
        {
            return other.Type.Equals(Type)
                && other.Value.Equals(Value);
        }

        public bool Equals(Claim other)
        {
            return other.Type.Equals(Type)
                && other.Value.Equals(Value);
        }
    }
}