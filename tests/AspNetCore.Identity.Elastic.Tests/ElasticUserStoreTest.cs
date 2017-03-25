using System;
using System.Linq;
using System.Security.Claims;
using Xunit;
using System.Threading;
using System.Threading.Tasks;
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
            var node = new Uri("http://localhost.:9200");
            var settings = new ConnectionSettings(node);
            settings.MapDefaultTypeIndices(m => m.Add(typeof(ElasticIdentityUser), _indexName));
            _elasticClient = new ElasticClient(settings);

            _store = new ElasticUserStore(_elasticClient);

            // the generic store refreshes immediately
            var store = new ElasticUserStore<string, ElasticIdentityUser>(_elasticClient);
            store.CreateAsync(_user1, CancellationToken.None).GetAwaiter().GetResult();
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
        public async Task CannotCreateDuplicateUser()
        {
            var result = await _store.CreateAsync(_user1, CancellationToken.None);

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