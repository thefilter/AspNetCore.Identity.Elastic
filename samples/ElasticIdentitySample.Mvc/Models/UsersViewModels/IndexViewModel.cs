using System.Collections.Generic;
using AspNetCore.Identity.Elastic;

namespace ElasticIdentitySample.Mvc.Models.UsersViewModels
{
    public class IndexViewModel
    {
        public IEnumerable<ElasticIdentityUser> Users { get; set; }
    }
}
