using System.ComponentModel.DataAnnotations;

namespace ElasticIdentitySample.Mvc.Models.AccountViewModels
{
    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
