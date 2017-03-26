using System;
using System.Linq;
using System.Security.Claims;
using Xunit;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Nest;

namespace AspNetCore.Identity.Elastic.Tests
{
    public class ElasticUserStoreTest : IDisposable
    {
        private readonly ElasticUserStore _store;
        private readonly ElasticClient _elasticClient;

        private readonly ElasticIdentityUser _user1 = new ElasticIdentityUser("user1")
        {
            Email = "user1@AspNetCore.Identity.Elastic.Tests"
        };

        private readonly ElasticIdentityUser _user2 = new ElasticIdentityUser("user2")
        {
            Email = "user2@AspNetCore.Identity.Elastic.Tests"
        };

        private readonly string _indexName;

        public ElasticUserStoreTest()
        {
            _indexName = Guid.NewGuid() + "users";
            var node = new Uri("http://127.0.0.1:9200");
            var settings = new ConnectionSettings(node);
            settings.MapDefaultTypeIndices(m => m.Add(typeof(ElasticIdentityUser), _indexName));
            _elasticClient = new ElasticClient(settings);

            _store = new ElasticUserStore(_elasticClient);

            // the generic store refreshes immediately
            var store = new ElasticUserStore<string, ElasticIdentityUser>(_elasticClient);
            store.CreateAsync(_user1, CancellationToken.None).GetAwaiter().GetResult();

            _elasticClient.Refresh(_indexName);
        }

        [Fact]
        public async Task CanCreateUser()
        {
            var result = await _store.CreateAsync(_user2, CancellationToken.None);

            Assert.True(result.Succeeded);
            var user = await _store.FindByIdAsync(_user2.Id, CancellationToken.None);
            Assert.Equal(_user2.Id, user.Id);
        }

        [Fact]
        public async Task CanCreateUserWithoutConstraints()
        {
            ElasticIdentityUser superUser = new ElasticIdentityUser("!£$%^&*()_+\"/[]{}@~#?¬`¦|€:;'ιϊνσα,.<>")
            {
                Email = "user2@AspNetCore.Identity.Elastic.Tests"
            };
            var result = await _store.CreateAsync(superUser, CancellationToken.None);

            Assert.True(result.Succeeded);
            var user = await _store.FindByIdAsync(superUser.Id, CancellationToken.None);
            Assert.Equal(superUser.Id, user.Id);
        }

        [Fact]
        public async Task CannotCreateDuplicateUser()
        {
            ElasticIdentityUser deleteUser = new ElasticIdentityUser("deletedUser")
            {
                Email = "deleteUser@AspNetCore.Identity.Elastic.Tests",
                DateDeleted = DateTimeOffset.UtcNow
            };

            await _store.CreateAsync(deleteUser, CancellationToken.None);

            var result = await _store.CreateAsync(deleteUser, CancellationToken.None);

            Assert.False(result.Succeeded);
        }

        [Fact]
        public async Task CanDeleteUser()
        {
            var user = await _store.FindByIdAsync(_user1.Id, CancellationToken.None);

            var deleteResult = await _store.DeleteAsync(user, CancellationToken.None);

            Assert.True(deleteResult.Succeeded);

            user = await _store.FindByIdAsync(_user1.Id, CancellationToken.None);

            Assert.Equal(null, user);
        }

        [Fact]
        public async Task CanFindByNameWhenUsedAsId()
        {
            await _store.CreateAsync(_user1, CancellationToken.None);

            var user = await _store.FindByNameAsync(_user1.NormalizedUserName, CancellationToken.None);

            Assert.Equal(_user1.UserName, user.UserName);
        }

        [Fact]
        public async Task CanFindByName()
        {
            var store = new ElasticUserStore<string, ElasticIdentityUser>(_elasticClient);

            var user = await store.FindByNameAsync(_user1.NormalizedUserName, CancellationToken.None);

            Assert.Equal(_user1.UserName, user.UserName);
        }

        [Fact]
        public async Task CanAddRoles()
        {
            const string roleName = "test";
            var user = await _store.FindByNameAsync(_user1.NormalizedUserName, CancellationToken.None);

            Assert.Empty(user.Roles);
            
            await _store.AddToRoleAsync(user, roleName, CancellationToken.None);
            await SaveToElastic(user);

            //reload
            user = await _store.FindByNameAsync(_user1.NormalizedUserName, CancellationToken.None);

            Assert.True(user.Roles.Select(role => role.RoleId).Contains(roleName));
        }

        [Fact]
        public async Task CanRemoveRoles()
        {
            const string roleName = "test";

            ElasticIdentityUser noRolesUser = new ElasticIdentityUser(nameof(noRolesUser));
            await _store.CreateAsync(noRolesUser, CancellationToken.None);

            var user = await _store.FindByNameAsync(noRolesUser.NormalizedUserName, CancellationToken.None);

            Assert.Empty(user.Roles);

            await _store.AddToRoleAsync(user, roleName, CancellationToken.None);
            await SaveToElastic(user);

            //reload
            user = await GetFromElastic(user.NormalizedUserName);
            Assert.NotEmpty(user.Roles);

            await _store.RemoveFromRoleAsync(user, roleName, CancellationToken.None);
            await SaveToElastic(user);

            user = await GetFromElastic(user.NormalizedUserName);

            Assert.Empty(user.Roles);
        }

        [Fact]
        public async Task CanAddClaim()
        {
            var claim = new Claim("testType", "testValue");
            var user = await _store.FindByNameAsync(_user1.NormalizedUserName, CancellationToken.None);

            Assert.Empty(user.Claims);

            await _store.AddClaimsAsync(user, new[] {claim}, CancellationToken.None);
            await SaveToElastic(user);

            user = await GetFromElastic(user.NormalizedUserName);

            Assert.NotEmpty(user.Claims);
        }

        [Fact]
        public async Task CanRemoveClaim()
        {
            var claim = new Claim("testType", "testValue");

            ElasticIdentityUser noClaimsUser = new ElasticIdentityUser(nameof(noClaimsUser));
            await _store.AddClaimsAsync(noClaimsUser, new[] { claim }, CancellationToken.None);
            await _store.CreateAsync(noClaimsUser, CancellationToken.None);

            var user = await _store.FindByNameAsync(noClaimsUser.NormalizedUserName, CancellationToken.None);

            Assert.NotEmpty(user.Claims);

            await _store.RemoveClaimsAsync(user, new[] { claim }, CancellationToken.None);
            await SaveToElastic(user);

            user = await GetFromElastic(user.NormalizedUserName);

            Assert.Empty(user.Claims);
        }

        [Fact]
        public async Task CanReplaceClaim()
        {
            ElasticIdentityUser noClaimsUser2 = new ElasticIdentityUser(nameof(noClaimsUser2));
            await _store.CreateAsync(noClaimsUser2, CancellationToken.None);

            var oldClaim = new Claim("testType", "testValue");
            var newClaim = new Claim("newTestType", "newTestValue");
            var user = await _store.FindByNameAsync(noClaimsUser2.NormalizedUserName, CancellationToken.None);
            await _store.AddClaimsAsync(user, new[] { oldClaim }, CancellationToken.None);
            await SaveToElastic(user);

            user = await GetFromElastic(user.NormalizedUserName);

            Assert.NotEmpty(user.Claims);

            await _store.ReplaceClaimAsync(user, oldClaim, newClaim, CancellationToken.None);
            await SaveToElastic(user);

            user = await GetFromElastic(user.NormalizedUserName);

            Assert.True(user.Claims.All(claim => claim.Type == newClaim.Type && claim.Value == newClaim.Value));
        }

        [Fact]
        public async Task CanGetUsersWithClaims()
        {
            var claimType11 = new Claim("claimType1", "valueType1");
            var claimType12 = new Claim("claimType2", "valueType1");
            var claimType21 = new Claim("claimType1", "valueType2");

            // user type 11
            ElasticIdentityUser noClaimsUser11 = new ElasticIdentityUser(nameof(noClaimsUser11));
            noClaimsUser11.Claims.Add(new ElasticIdentityUserClaim(claimType11));
            await _store.CreateAsync(noClaimsUser11, CancellationToken.None);

            // user type 12
            ElasticIdentityUser noClaimsUser12 = new ElasticIdentityUser(nameof(noClaimsUser12));
            noClaimsUser12.Claims.Add(new ElasticIdentityUserClaim(claimType12));
            noClaimsUser12.Claims.Add(new ElasticIdentityUserClaim(claimType21));
            await _store.CreateAsync(noClaimsUser12, CancellationToken.None);

            // user type 21
            ElasticIdentityUser noClaimsUser21 = new ElasticIdentityUser(nameof(noClaimsUser21));
            noClaimsUser21.Claims.Add(new ElasticIdentityUserClaim(claimType21));
            noClaimsUser21.Claims.Add(new ElasticIdentityUserClaim(claimType12));
            await _store.CreateAsync(noClaimsUser21, CancellationToken.None);

            _elasticClient.Refresh(_indexName);

            var users = await _store.GetUsersForClaimAsync(claimType11, CancellationToken.None);

            Assert.Equal(nameof(noClaimsUser11), users.FirstOrDefault().UserName);
        }

        [Fact]
        public async Task CanAddLogins()
        {
            var loginInfo = new UserLoginInfo("loginProvider", "key-123", "Login Provider");
            var user = await _store.FindByNameAsync(_user1.NormalizedUserName, CancellationToken.None);

            Assert.Empty(user.Logins);

            await _store.AddLoginAsync(user, loginInfo, CancellationToken.None);
            await SaveToElastic(user);

            user = await GetFromElastic(user.NormalizedUserName);

            Assert.NotEmpty(user.Logins);
        }

        [Fact]
        public async Task CanRemoveLogin()
        {
            var loginInfo = new UserLoginInfo("loginProvider", "key-123", "Login Provider");

            ElasticIdentityUser noLoginsUser = new ElasticIdentityUser(nameof(noLoginsUser));
            await _store.AddLoginAsync(noLoginsUser, loginInfo, CancellationToken.None);
            await _store.CreateAsync(noLoginsUser, CancellationToken.None);

            var user = await _store.FindByNameAsync(noLoginsUser.NormalizedUserName, CancellationToken.None);

            Assert.NotEmpty(user.Logins);

            await _store.RemoveLoginAsync(user, loginInfo.LoginProvider, loginInfo.ProviderKey, CancellationToken.None);
            await SaveToElastic(user);

            user = await GetFromElastic(user.NormalizedUserName);

            Assert.Empty(user.Logins);
        }

        [Fact]
        public async Task CanFindByLogin()
        {
            var type11 = new ElasticIdentityUserLogin("loginProvider1", "providerKey1", "Login Provider 1");
            var type12 = new ElasticIdentityUserLogin("loginProvider1", "providerKey2", "Login Provider 1");
            var type21 = new ElasticIdentityUserLogin("loginProvider2", "providerKey1", "Login Provider 2");

            // user type 11
            ElasticIdentityUser user11 = new ElasticIdentityUser(nameof(user11));
            user11.Logins.Add(type11);
            await _store.CreateAsync(user11, CancellationToken.None);

            // user type 12
            ElasticIdentityUser user12 = new ElasticIdentityUser(nameof(user12));
            user12.Logins.Add(type12);
            user12.Logins.Add(type21);
            await _store.CreateAsync(user12, CancellationToken.None);

            // user type 21
            ElasticIdentityUser user21 = new ElasticIdentityUser(nameof(user21));
            user21.Logins.Add(type21);
            user21.Logins.Add(type12);
            await _store.CreateAsync(user21, CancellationToken.None);

            _elasticClient.Refresh(_indexName);

            var user = await _store.FindByLoginAsync(type11.LoginProvider, type11.ProviderKey, CancellationToken.None);

            Assert.Equal(nameof(user11), user.UserName);
        }

        private async Task<ElasticIdentityUser> GetFromElastic(string userName)
        {
            return await _store.FindByNameAsync(userName, CancellationToken.None);
        }

        private async Task SaveToElastic(ElasticIdentityUser user)
        {
            await _store.UpdateAsync(user, CancellationToken.None);
        }

        public void Dispose()
        {
            _elasticClient.DeleteIndex(_indexName);
        }
    }
}