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
        /// Registers singleton <see cref="ElasticUserStore"/> component for 
        /// <see cref="IUserStore{ElasticIdentityUser}"/> with the parameters supplied by the provided 
        /// <see cref="ElasticUserStoreOptions"/>, and registers dependencies for that component which have not already been 
        /// registered.
        /// </summary>
        /// <param name="elasticClient">
        /// The <see cref="IElasticClient"/> which will be used by the <see cref="ElasticUserStore"/>.
        /// </param>
        public static void AddElasticIdentity(
            this IServiceCollection services, 
            IElasticClient elasticClient)
        {
            services.TryAddSingleton<IElasticClient>(elasticClient);

            services.AddSingleton<IUserStore<ElasticIdentityUser>, ElasticUserStore>();

            services.TryAddSingleton<IdentityMarkerService>();
            services.TryAddSingleton<IUserValidator<ElasticIdentityUser>, UserValidator<ElasticIdentityUser>>();
            services.TryAddSingleton<IPasswordValidator<ElasticIdentityUser>, PasswordValidator<ElasticIdentityUser>>();
            services.TryAddSingleton<IPasswordHasher<ElasticIdentityUser>, PasswordHasher<ElasticIdentityUser>>();
            services.TryAddSingleton<ILookupNormalizer, LowerInvariantLookupNormalizer>();
            services.TryAddSingleton<IdentityErrorDescriber>();
            services.TryAddSingleton<ISecurityStampValidator, SecurityStampValidator<ElasticIdentityUser>>();
            services.TryAddSingleton<IUserClaimsPrincipalFactory<ElasticIdentityUser>, UserClaimsPrincipalFactory<ElasticIdentityUser>>();
            services.TryAddSingleton<UserManager<ElasticIdentityUser>, UserManager<ElasticIdentityUser>>();
            services.TryAddScoped<SignInManager<ElasticIdentityUser>, SignInManager<ElasticIdentityUser>>();
        }

        /// <summary>
        /// Registers singleton <see cref="ElasticUserStore"/> component for 
        /// <see cref="IUserStore{ElasticIdentityUser}"/> with the parameters supplied by the provided 
        /// <see cref="ElasticUserStoreOptions"/>, and registers dependencies for that component which have not already been 
        /// registered.
        /// </summary>
        /// <param name="serverName">
        /// The server:port combination which the <see cref="ElasticUserStore"/> will connect to. E.g. localhost:9200
        /// </param>
        /// <param name="indexName">
        /// The index which will contain the user information.
        /// </param>
        public static void AddElasticIdentity(
            this IServiceCollection services, 
            string serverName, 
            string indexName = DEFAULT_INDEX_NAME)
        {
            var node = new Uri("http://" + serverName.Replace("http://", ""));            

            IElasticClient elasticClient = ElasticClientFactory.Create(node, indexName);
            
            AddElasticIdentity(services, elasticClient);
        }
    }
}
