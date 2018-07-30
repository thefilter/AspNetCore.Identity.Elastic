using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Nest;

namespace AspNetCore.Identity.Elastic.Extensions
{
    public static class ServiceExtensions
    {
        private const string DEFAULT_INDEX_NAME = "users";

        /// <summary>
        /// Configures the identity builder with ElasticIdentity components,
        /// and registers dependencies for that component which have not already been 
        /// registered.
        /// </summary>
        /// <param name="elasticClient">
        /// The <see cref="IElasticClient"/> which will be used by the <see cref="ElasticUserStore"/>.
        /// </param>
        public static IdentityBuilder AddElasticIdentity(this IdentityBuilder identityBuilder, 
            IElasticClient elasticClient)
        {
            identityBuilder.AddUserStore<ElasticUserStore<string, ElasticIdentityUser>>();
            identityBuilder.AddRoleStore<ElasticIdentityUserRole>();
            identityBuilder.AddUserValidator<UserValidator<ElasticIdentityUser>>();
            identityBuilder.AddPasswordValidator<PasswordValidator<ElasticIdentityUser>>();
            identityBuilder.AddSignInManager<SignInManager<ElasticIdentityUser>>();
            identityBuilder.AddUserManager<UserManager<ElasticIdentityUser>>();
            identityBuilder.AddClaimsPrincipalFactory<UserClaimsPrincipalFactory<ElasticIdentityUser>>();
            identityBuilder.AddErrorDescriber<IdentityErrorDescriber>();

            identityBuilder.Services.TryAddSingleton<IElasticClient>(elasticClient);
            identityBuilder.Services.TryAddSingleton<IPasswordHasher<ElasticIdentityUser>, PasswordHasher<ElasticIdentityUser>>();
            identityBuilder.Services.TryAddSingleton<ILookupNormalizer, LowerInvariantLookupNormalizer>();
            identityBuilder.Services.TryAddSingleton<ISecurityStampValidator, SecurityStampValidator<ElasticIdentityUser>>();
        
            return identityBuilder;
        }

        /// <summary>
        /// Configures the identity builder with ElasticIdentity components,
        /// and registers dependencies for that component which have not already been 
        /// registered.
        /// </summary>
        /// <param name="serverName">
        /// The server:port combination which the <see cref="ElasticUserStore"/> will connect to. E.g. localhost:9200
        /// </param>
        /// <param name="indexName">
        /// The index which will contain the user information.
        /// </param>
        public static IdentityBuilder AddElasticIdentity(
            this IdentityBuilder identityBuilder,
            string serverName,
            string indexName = DEFAULT_INDEX_NAME)
        {
            var node = new Uri("http://" + serverName.Replace("http://", ""));

            IElasticClient elasticClient = ElasticClientFactory.Create(node, indexName);

            return AddElasticIdentity(identityBuilder, elasticClient);
        }
    }
}
