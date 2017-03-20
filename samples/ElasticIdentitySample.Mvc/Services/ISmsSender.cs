using System.Threading.Tasks;

namespace ElasticIdentitySample.Mvc.Services
{
    public interface ISmsSender
    {
        Task SendSmsAsync(string number, string message);
    }
}
