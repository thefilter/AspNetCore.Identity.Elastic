using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Elasticsearch.Net;
using Microsoft.AspNetCore.Identity;
using Nest;

namespace AspNetCore.Identity.Elastic
{
    /// <summary>
    /// The default implementation of <see cref="ElasticUserStore{TKey, TUser}"/> where Tkey is <see cref="string"/> and TUser is <see cref="ElasticIdentityUser"/>.
    /// <para />
    /// This implementation uses elastisearch explicit version numbering for concurrency control.
    /// </summary>
    public class ElasticUserStore : ElasticUserStore<string, ElasticIdentityUser>
    {
        public ElasticUserStore(IElasticClient elasticClient) : base(elasticClient)
        {
        }

        public ElasticUserStore(Uri elasticServerUri, string indexName) : base(elasticServerUri, indexName)
        {
        }

        public override async Task<IdentityResult> CreateAsync(ElasticIdentityUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var existingUser = await GetUserById(user.Id, cancellationToken);

            if (existingUser != null)
            {
                return IdentityResult.Failed(ERROR_DESCRIBER.DuplicateUserName(user.UserName));
            }

            var result = await ELASTIC_CLIENT.CreateAsync(user, null, cancellationToken);

            return result.IsValid ? IdentityResult.Success : IdentityResult.Failed();
        }

        /// <summary>
        /// Logically deletes the <paramref name="user"/> from the user store.
        /// </summary>
        /// <param name="user">The user to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
        public override async Task<IdentityResult> DeleteAsync(ElasticIdentityUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.DateDeleted = DateTimeOffset.UtcNow;

            var result = await ELASTIC_CLIENT
                .UpdateAsync(new DocumentPath<ElasticIdentityUser>(user),
                    d => d
                        .Doc(user)
                        .Version(user.Version ?? 1)
                        .Refresh(Refresh.True),
                    cancellationToken);

            return result.IsValid
                ? IdentityResult.Success
                : IdentityResult.Failed(ERROR_DESCRIBER.ConcurrencyFailure());
        }

        public override async Task<ElasticIdentityUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (normalizedUserName == null)
            {
                throw new ArgumentNullException(nameof(normalizedUserName));
            }

            var lowerInvariantUserName = normalizedUserName.ToLowerInvariant();

            var user = await GetUserById(lowerInvariantUserName, cancellationToken);

            return user;
        }

        public override Task SetUserNameAsync(ElasticIdentityUser user, string userName, CancellationToken cancellationToken)
        {
            throw new NotSupportedException("Changing user name is not supported.");
        }

        public override async Task<IdentityResult> UpdateAsync(ElasticIdentityUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var indexResponse = await ELASTIC_CLIENT
                .IndexAsync(user, x => x.Version(user.Version ?? 1), cancellationToken);

            return indexResponse.IsValid
                ? IdentityResult.Success
                : IdentityResult.Failed(ERROR_DESCRIBER.ConcurrencyFailure());
        }
    }

    public class ElasticUserStore<TKey, TUser> :
        IUserLoginStore<TUser>,
        IUserClaimStore<TUser>,
        IUserRoleStore<TUser>,
        IUserPasswordStore<TUser>,
        IUserSecurityStampStore<TUser>,
        IUserTwoFactorStore<TUser>,
        IUserEmailStore<TUser>,
        IUserLockoutStore<TUser>,
        IUserPhoneNumberStore<TUser>,
        IQueryableUserStore<TUser>
        where TKey : IEquatable<TKey>
        where TUser : ElasticIdentityUser<TKey>
    {
        protected readonly IElasticClient ELASTIC_CLIENT;
        protected readonly IdentityErrorDescriber ERROR_DESCRIBER = new IdentityErrorDescriber();
        private readonly string _indexName;
        private bool _disposed;

        public ElasticUserStore(IElasticClient elasticClient)
        {
            if (elasticClient == null)
            {
                throw new ArgumentNullException(nameof(elasticClient));
            }

            string indexName;
            elasticClient.ConnectionSettings.DefaultIndices.TryGetValue(typeof(TUser), out indexName);

            if (string.IsNullOrEmpty(indexName))
            {
                indexName = elasticClient.ConnectionSettings.DefaultIndex;
            }

            if (string.IsNullOrEmpty(indexName))
            {
                throw new ArgumentNullException(indexName, "Index name must be specified either through ConnectionSettings.MapDefaultTypeIndices or DefaultIndex");
            }

            ELASTIC_CLIENT = elasticClient;
            _indexName = indexName;

            EnsureIndexExists();
        }

        public ElasticUserStore(Uri elasticServerUri, string indexName)
            : this(new ElasticClient(new ConnectionSettings(elasticServerUri)
                .ThrowExceptions()
                .MapDefaultTypeIndices(x => x.Add(typeof(TUser), indexName))))
        {
        }

        public IQueryable<TUser> Users
        {
            get
            {
                var sd = new SearchDescriptor<TUser>()
                    .Version()
                    .Query(q => q
                        .Bool(b => b
                            .MustNot(
                                bmn => bmn.Exists(f => f.Field(u => u.DateDeleted))
                            )
                        )
                    );

                return ELASTIC_CLIENT.Search<TUser>(sd).Documents.AsQueryable();
            }
        }

        public Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            foreach (var claim in claims.Select(c => new ElasticIdentityUserClaim(c)))
            {
                if (!user.Claims.Contains(claim))
                { 
                    user.Claims.Add(claim);
                }
            }

            return Task.CompletedTask;
        }

        public Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (login == null)
            {
                throw new ArgumentNullException(nameof(login));
            }

            if (user.Logins.Any(l => l.Equals(login)))
            {
                throw new InvalidOperationException($"A login for this provider ({login.ProviderDisplayName}) already exists.");
            }

            user.Logins.Add(ElasticIdentityUserLogin.FromUserLoginInfo(login));

            return Task.CompletedTask;
        }

        public virtual async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var result = await ELASTIC_CLIENT.CreateAsync(user, d => d.Refresh(Refresh.True), cancellationToken);

            return  result.IsValid? IdentityResult.Success : IdentityResult.Failed();
        }

        /// <summary>
        /// Deletes the <paramref name="user"/> from the user store.
        /// </summary>
        /// <param name="user">The user to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
        public virtual async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var result = await ELASTIC_CLIENT.DeleteAsync(DocumentPath<TUser>.Id(user), d => d
                    .Version(user.Version ?? 1)
                    .Refresh(Refresh.True)
                , cancellationToken);

            return result.IsValid ? IdentityResult.Success : IdentityResult.Failed(new IdentityError{Description = result.Result.ToString()});
        }

        /// <summary>
        /// Dispose the store
        /// </summary>
        public void Dispose()
        {
            _disposed = true;
        }

        public async Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (normalizedEmail == null)
            {
                throw new ArgumentNullException(nameof(normalizedEmail));
            }

            var sd = new SearchDescriptor<TUser>()
                .Version()
                .Query(q => q
                    .Bool(b => b
                        .Must(
                            bm => bm.
                                Term(t => t
                                    .Field(tf => tf.NormalizedEmail.Suffix("keyword"))
                                    .Value(normalizedEmail.ToLowerInvariant())
                                )
                        )
                        .MustNot(
                            bmn => bmn.Exists(f => f.Field(u => u.DateDeleted))
                        )
                    )
                );

            var result = await ELASTIC_CLIENT.SearchAsync<TUser>(sd, cancellationToken);

            return GetFirstUserOrDefault(result);
        }

        public async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }

            var user = await GetUserById(userId, cancellationToken);

            return user;
        }

        public async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }
            if (providerKey == null)
            {
                throw new ArgumentNullException(nameof(providerKey));
            }

            var sd = new SearchDescriptor<TUser>()
                .Version()
                .Size(1)
                .Query(q => q
                    .Bool(b => b
                        .Must(
                            bm => bm.Term(u => u.Logins.First().LoginProvider.Suffix("keyword"), loginProvider),
                            bm => bm.Term(u => u.Logins.First().ProviderKey.Suffix("keyword"), providerKey)
                        )
                        .MustNot(
                            bmn => bmn.Exists(f => f.Field(u => u.DateDeleted))
                        )

                    )
                );

            var result = await ELASTIC_CLIENT.SearchAsync<TUser>(sd, cancellationToken);

            if (!result.IsValid)
            {
                return null;
            }

            return result.Hits
                .Where(h => h.Source != null)
                .Select(u =>
                {
                    var user = u.Source;
                    user.Version = u.Version;
                    return user;
                })
                // assuming that logins are not nested
                .FirstOrDefault(u => u.Logins.Any(c => c.LoginProvider == loginProvider && c.ProviderKey == providerKey));
        }

        public virtual async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (normalizedUserName == null)
            {
                throw new ArgumentNullException(nameof(normalizedUserName));
            }

            var lowerInvariantUserName = normalizedUserName.ToLowerInvariant();

            var sd = new SearchDescriptor<TUser>()
                .Version()
                .Size(1)
                .Query(q => q
                    .Bool(b => b
                        .Must(
                            bm => bm.Term(u => u.NormalizedUserName.Suffix("keyword"), lowerInvariantUserName)
                        )
                        .MustNot(
                            bmn => bmn.Exists(f => f.Field(u => u.DateDeleted))
                        )
                    )
                );

            var result = await ELASTIC_CLIENT.SearchAsync<TUser>(sd, cancellationToken);
            var user = GetFirstUserOrDefault(result);
            return user;
        }

        public Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var result = (IList<Claim>) user
                .Claims
                .Select(x => x.ToClaim())
                .ToList();

            return Task.FromResult(result);
        }

        public Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.Email == null)
            {
                throw new InvalidOperationException("User doesn't have an email.");
            }

            return Task.FromResult(user.EmailConfirmed);
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.IsLockoutEnabled);
        }

        public Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var lockoutEndDate = user.LockoutEndDate;

            return Task.FromResult(lockoutEndDate);
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var userLoginInfos = (IList<UserLoginInfo>) user.Logins.Select(l => l.ToUserLoginInfo()).ToList();

            return Task.FromResult(userLoginInfos);
        }

        public Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.NormalizedEmail);
        }

        public Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.NormalizedUserName);
        }

        public Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.PasswordHash);
        }

        public Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.SecurityStamp);
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.IsTwoFactorEnabled);
        }

        public async Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return await Task.FromResult(user.Id.ToString());
        }

        public Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.UserName);
        }

        public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            var sd = new SearchDescriptor<TUser>()
                .Version()
                .Size(10000)
                .Query(q => q
                    .Bool(b => b
                        .Must(
                            bm => bm.Term(u => u.Claims.First().Type.Suffix("keyword"), claim.Type),
                            bm => bm.Term(u => u.Claims.First().Value.Suffix("keyword"), claim.Value)
                        )
                        .MustNot(
                            bmn => bmn.Exists(f => f.Field(u => u.DateDeleted))
                        )

                    )
                );

            var result = await ELASTIC_CLIENT.SearchAsync<TUser>(sd, cancellationToken);

            if (!result.IsValid)
            {
                return null;
            }

            return result.Hits
                .Where(h => h.Source != null)
                .Select(u =>
                {
                    var user = u.Source;
                    user.Version = u.Version;
                    return user;
                })
                // assuming that claims is not nested
                .Where(u => u.Claims.Any(c => c.Type == claim.Type && c.Value == claim.Value))
                .ToList();
        }

        public Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.PasswordHash != null);
        }

        public async Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.AccessFailedCount++;

            return await Task.FromResult(user.AccessFailedCount);
        }

        public Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            var elasticClaims = claims.Select(claim => new ElasticIdentityUserClaim(claim));

            foreach (var claim in elasticClaims)
            {
                user.Claims.Remove(claim);
            }
    
            return Task.CompletedTask;
        }

        public Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (providerKey == null)
            {
                throw new ArgumentNullException(nameof(providerKey));
            }

            var login = user.Logins.FirstOrDefault(l => l.LoginProvider == providerKey && l.LoginProvider == loginProvider);

            if (login != null)
            {
                user.Logins.Remove(login);
            }

            return Task.CompletedTask;
        }

        public Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            var elasticClaim = new ElasticIdentityUserClaim(claim);
            user.Claims.Remove(elasticClaim);
            user.Claims.Add(new ElasticIdentityUserClaim(newClaim));
            return Task.CompletedTask;
        }

        public Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.ResetAccessFailedCount();

            return Task.CompletedTask;
        }

        public Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (email == null)
            {
                throw new ArgumentNullException(nameof(email));
            }

            user.Email = email;

            return Task.CompletedTask;
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (user.Email == null)
            {
                throw new InvalidOperationException("User doesn't have an email.");
            }

            if (confirmed)
            {
                user.SetEmailConfirmed();
            }
            else
            {
                user.SetEmailConfirmed();
            }

            return Task.CompletedTask;
        }

        public Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.IsLockoutEnabled = enabled;

            return Task.CompletedTask;
        }

        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (lockoutEnd != null)
            {
                user.LockUntil(lockoutEnd.Value);
            }

            return Task.CompletedTask;
        }

        public Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.PasswordHash = passwordHash;
            user.LastPasswordChangedDate = DateTimeOffset.UtcNow;

            return Task.CompletedTask;
        }

        public Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (stamp == null)
            {
                throw new ArgumentNullException(nameof(stamp));
            }

            user.SecurityStamp = stamp;

            return Task.CompletedTask;
        }

        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.IsTwoFactorEnabled = enabled;

            return Task.CompletedTask;
        }

        public virtual Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (userName == null)
            {
                throw new ArgumentNullException(nameof(userName));
            }

            user.UserName = userName;

            return Task.CompletedTask;
        }

        public virtual async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrEmpty(user.Id?.ToString()))
            {
                throw new ArgumentNullException(nameof(user.Id),
                    "A null or empty User.Id value is not allowed.");
            }

            var indexResponse = await ELASTIC_CLIENT
                .IndexAsync(user, x => x.Refresh(Refresh.True), cancellationToken);

            return indexResponse.IsValid 
                ? IdentityResult.Success 
                : IdentityResult.Failed(ERROR_DESCRIBER.ConcurrencyFailure());
        }

        public async Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (roleName == null)
            {
                throw new ArgumentNullException(nameof(roleName));
            }

            if (await IsInRoleAsync(user, roleName, cancellationToken))
            {
                return;
            }

            var role = new ElasticIdentityUserRole(roleName);
            user.Roles.Add(role);
        }

        public Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (roleName == null)
            {
                throw new ArgumentNullException(nameof(roleName));
            }

            user.Roles.Remove(new ElasticIdentityUserRole(roleName));

            return Task.CompletedTask;
        }

        public Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var roles = user.Roles.Select(r => r.RoleId).ToList();

            return Task.FromResult((IList<string>) roles);
        }

        public async Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (roleName == null)
            {
                throw new ArgumentNullException(nameof(roleName));
            }

            var roles = await GetRolesAsync(user, cancellationToken);

            return await Task.FromResult(roles.Contains(roleName));
        }

        public async Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (roleName == null)
            {
                throw new ArgumentNullException(nameof(roleName));
            }

            var sd = new SearchDescriptor<TUser>()
                .Version()
                .Size(10000)
                .Query(q => q
                    .Bool(b => b
                        .Must(
                            bm => bm.Term(u => u.Roles.Suffix("keyword"), roleName)
                        )
                        .MustNot(
                            bmn => bmn.Exists(f => f.Field(u => u.DateDeleted))
                        )
                    )
                );

            var result = await ELASTIC_CLIENT.SearchAsync<TUser>(sd, cancellationToken);

            return result.Hits.Where(h => h.Source != null).Select(u =>
                {
                    var user = u.Source;
                    user.Version = u.Version;
                    return user;
                })
                .ToList();
        }

        public Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.PhoneNumber = phoneNumber;

            return Task.CompletedTask;
        }

        public Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return  Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.PhoneNumberConfirmed = confirmed;

            return Task.CompletedTask;
        }

        /// <summary>
        /// Throws if this class has been disposed.
        /// </summary>
        protected void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }

        protected async Task<TUser> GetUserById(string userId, CancellationToken cancellationToken)
        {
            var getResponse = await ELASTIC_CLIENT.GetAsync(DocumentPath<TUser>.Id(userId), cancellationToken: cancellationToken);

            var user = getResponse.Found ? getResponse.Source : null;

            if (user == null || user.DateDeleted != null)
            {
                return null;
            }

            user.Version = getResponse.Version;

            return user;
        }

        private static TUser GetFirstUserOrDefault(ISearchResponse<TUser> result)
        {
            var hit = result.Hits.FirstOrDefault();
            var user = hit?.Source;
            if (user != null)
            {
                user.Version = hit.Version;
            }
            return user;
        }

        private void EnsureIndexExists()
        {
            var indexExists = ELASTIC_CLIENT.IndexExists(new IndexExistsRequest(_indexName)).Exists;

            if (indexExists)
            {
                return;
            }

            var response = ELASTIC_CLIENT.CreateIndex(_indexName, GetIndexMappings);

            if (!response.ApiCall.Success)
            {
                throw new Exception($"Error while creating index:\n{response.DebugInformation}");
            }
        }

        private static ICreateIndexRequest GetIndexMappings(CreateIndexDescriptor createIndexDescriptor)
        {
            return createIndexDescriptor.Mappings(m => m
                .Map<TUser>(mm => mm
                    .AutoMap()
                    .AllField(af => af
                        .Enabled(false))
                )
            );
        }
    }
}
