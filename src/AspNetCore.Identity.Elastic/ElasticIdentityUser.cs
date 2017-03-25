using System;
using System.Collections.Generic;
using System.Linq;

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
        public ElasticIdentityUser()
        {
            DateCreated = DateTimeOffset.UtcNow;
        }

        public ElasticIdentityUser(string userName) : this()
        {
            UserName = userName;
        }

        public TKey Id { get; set; }

        public string UserName { get; set; }

        public string NormalizedUserName => UserName.ToLowerInvariant();

        public string Email { get; set; }

        public string NormalizedEmail => Email?.ToLowerInvariant();

        public bool EmailConfirmed { get; set; }

        public string PhoneNumber { get; set; }

        public bool PhoneNumberConfirmed { get; set; }

        public bool IsLockoutEnabled { get; set; }

        public string PasswordHash { get; set; }

        public string SecurityStamp { get; set; }

        public int AccessFailedCount { get; set; }

        public DateTimeOffset DateCreated { get; private set; }

        public DateTimeOffset? DateDeleted { get; set; } = null;

        public DateTimeOffset? LastLoginDate { get; set; } = null;

        public DateTimeOffset? LastPasswordChangedDate { get; set; } = null;

        public ICollection<TUserRole> Roles { get; set; } = new List<TUserRole>();

        public ICollection<TUserClaim> Claims { get; set; } = new List<TUserClaim>();

        public ICollection<TUserLogin> Logins { get; set; } = new List<TUserLogin>();

        public DateTimeOffset? LockoutEndDate { get; set; }

        public bool IsTwoFactorEnabled { get; set; }

        internal long? Version { get; set; }

        internal void LockUntil(DateTimeOffset utcDateTime)
        {
            LockoutEndDate = utcDateTime;
        }

        internal void SetEmailConfirmed()
        {
            EmailConfirmed = true;
        }

        internal void ResetAccessFailedCount()
        {
            AccessFailedCount = 0;
        }
    }
}