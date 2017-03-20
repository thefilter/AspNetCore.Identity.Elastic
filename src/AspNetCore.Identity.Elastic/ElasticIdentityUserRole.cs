using Nest;

namespace AspNetCore.Identity.Elastic
{
    public class ElasticIdentityUserRole
    {
        public ElasticIdentityUserRole(string roleId)
        {
            RoleId = roleId;
        }

        [Keyword]
        public string RoleId { get; set; }
    }
}