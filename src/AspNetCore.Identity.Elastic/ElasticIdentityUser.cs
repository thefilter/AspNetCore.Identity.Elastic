using System;
using System.Collections.Generic;
using Nest;
using Newtonsoft.Json;

namespace AspNetCore.Identity.Elastic
{
    /// <summary>
    /// The default implementation of <see cref="ElasticIdentityUser{TKey}"/> which uses the user name as id.
    /// </summary>
    public class ElasticIdentityUser : ElasticIdentityUser<string>
    {
        public ElasticIdentityUser(string userName)
        {
            UserName = userName;
            Id = userName.ToLowerInvariant();
        }
    }

    public class ElasticIdentityUser<TKey> :
        ElasticIdentityUser<TKey, ElasticIdentityUserClaim, ElasticIdentityUserRole, ElasticIdentityUserLogin>
        where TKey : IEquatable<TKey>
    {
    }

    public class ElasticIdentityUser<TKey, TUserClaim, TUserRole, TUserLogin>
        where TKey : IEquatable<TKey>
    {
        private const string ISO_DATE_FORMAT = "strict_date_time";

        public ElasticIdentityUser()
        {
        }

        public ElasticIdentityUser(string userName) : this()
        {
            UserName = userName;
        }

        [Keyword]
        public TKey Id { get; set; }

        public string UserName { get; set; }

        [Keyword]
        public string NormalizedUserName => UserName.ToLowerInvariant();

        [Keyword]
        public string Email { get; set; }

        [Keyword]
        public string NormalizedEmail => Email?.ToLowerInvariant();

        public bool EmailConfirmed { get; set; }

        [Keyword]
        public string PhoneNumber { get; set; }

        public bool PhoneNumberConfirmed { get; set; }

        public bool IsLockoutEnabled { get; set; }

        [Keyword]
        public string PasswordHash { get; set; }

        [Keyword]
        public string SecurityStamp { get; set; }

        public int AccessFailedCount { get; set; }

        public bool IsTwoFactorEnabled { get; set; }

        [Date(Format = ISO_DATE_FORMAT)]
        [JsonConverter(typeof(UtcIsoDateTimeConverter))]
        public DateTimeOffset DateCreated { get; set; } = DateTimeOffset.UtcNow;

        [Date(Format = ISO_DATE_FORMAT)]
        [JsonConverter(typeof(UtcIsoDateTimeConverter))]
        public DateTimeOffset? DateDeleted { get; set; } = null;

        [Date(Format = ISO_DATE_FORMAT)]
        [JsonConverter(typeof(UtcIsoDateTimeConverter))]
        public DateTimeOffset? LastLoginDate { get; set; } = null;

        [Date(Format = ISO_DATE_FORMAT)]
        [JsonConverter(typeof(UtcIsoDateTimeConverter))]
        public DateTimeOffset? LastPasswordChangedDate { get; set; } = null;

        [Date(Format = ISO_DATE_FORMAT)]
        [JsonConverter(typeof(UtcIsoDateTimeConverter))]
        public DateTimeOffset? LockoutEndDate { get; set; }

        [Nested(IncludeInParent = true)]
        public ICollection<TUserRole> Roles { get; set; } = new List<TUserRole>();

        [Nested(IncludeInParent = true)]
        public ICollection<TUserClaim> Claims { get; set; } = new List<TUserClaim>();

        [Nested(IncludeInParent = true)]
        public ICollection<TUserLogin> Logins { get; set; } = new List<TUserLogin>();

        internal long? Version { get; set; }

        internal void LockUntil(DateTimeOffset utcDateTime)
        {
            LockoutEndDate = utcDateTime;
        }

        internal void ResetAccessFailedCount()
        {
            AccessFailedCount = 0;
        }
    }
}