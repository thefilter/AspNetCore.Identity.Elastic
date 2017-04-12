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

        public static void AddElasticIdentity(this IServiceCollection services, IElasticClient elasticClient)
        {
            services.AddSingleton<IUserStore<ElasticIdentityUser>>(provider => new ElasticUserStore(elasticClient));
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

        public static void AddElasticIdentity(this IServiceCollection services, string serverName, string indexName = DEFAULT_INDEX_NAME)
        {
            var node = new Uri("http://" + serverName.Replace("http://", ""));

            IElasticClient elasticClient = ElasticClientFactory.Create(node, indexName);
            
            AddElasticIdentity(services, elasticClient);
        }
    }
}
