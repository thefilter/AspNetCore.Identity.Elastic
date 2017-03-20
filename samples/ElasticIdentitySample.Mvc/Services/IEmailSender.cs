using System.Threading.Tasks;

namespace ElasticIdentitySample.Mvc.Services
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string email, string subject, string message);
    }
}
