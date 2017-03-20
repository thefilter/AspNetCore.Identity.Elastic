using System;
using System.Security.Claims;

namespace AspNetCore.Identity.Elastic
{
    public class ElasticIdentityUserClaim : ElasticIdentityUserClaim<string>
    {
        public ElasticIdentityUserClaim(Claim claim)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            ClaimType = claim.Type;
            ClaimValue = claim.Value;
        }
    }

    public class ElasticIdentityUserClaim<TKey> where TKey : IEquatable<TKey>
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

            ClaimType = claim.Type;
            ClaimValue = claim.Value;
        }

        public ElasticIdentityUserClaim(string claimType, string claimValue)
        {
            ClaimType = claimType ?? throw new ArgumentNullException(nameof(claimType));
            ClaimValue = claimValue ?? throw new ArgumentNullException(nameof(claimValue));
        }

        public int Id { get; set; }

        public string ClaimType { get; set; }

        public string ClaimValue { get; set; }

        public Claim ToClaim()
        {
            return new Claim(ClaimType, ClaimValue);
        }

        public void InitializeFromClaim(Claim claim)
        {
            ClaimType = claim.Type;
            ClaimValue = claim.Value;
        }
    }
}