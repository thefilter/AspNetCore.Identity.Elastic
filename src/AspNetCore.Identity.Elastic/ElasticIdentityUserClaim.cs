using System;
using System.Security.Claims;

namespace AspNetCore.Identity.Elastic
{
    public class ElasticIdentityUserClaim
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
            Type = claimType ?? throw new ArgumentNullException(nameof(claimType));
            Value = claimValue ?? throw new ArgumentNullException(nameof(claimValue));
        }

        public string Type { get; set; }

        public string Value { get; set; }

        public Claim ToClaim()
        {
            return new Claim(Type, Value);
        }
    }
}