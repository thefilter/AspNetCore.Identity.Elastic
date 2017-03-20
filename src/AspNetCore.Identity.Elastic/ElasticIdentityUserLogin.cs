using System;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.Elastic
{
    public class ElasticIdentityUserLogin: IEquatable<ElasticIdentityUserLogin>, IEquatable<UserLoginInfo>
    {
        public ElasticIdentityUserLogin(string loginProvider, string providerKey, string displayName)
        {
            LoginProvider = loginProvider;
            ProviderKey = providerKey;
            ProviderDisplayName = displayName;
        }

        public UserLoginInfo ToUserLoginInfo()
        {
            return new UserLoginInfo(LoginProvider, ProviderKey, ProviderDisplayName);
        }

        public string ProviderDisplayName { get; set; }

        public string ProviderKey { get; set; }

        public string LoginProvider { get; set; }

        public bool Equals(ElasticIdentityUserLogin other)
        {
            return other.LoginProvider.Equals(LoginProvider)
                && other.ProviderKey.Equals(ProviderKey);
        }

        public bool Equals(UserLoginInfo other)
        {
            return other.LoginProvider.Equals(LoginProvider)
                && other.ProviderKey.Equals(ProviderKey);
        }

        public static ElasticIdentityUserLogin FromUserLoginInfo(UserLoginInfo userLoginInfo)
        {
            return new ElasticIdentityUserLogin(userLoginInfo.LoginProvider, userLoginInfo.ProviderKey, userLoginInfo.ProviderDisplayName);
        }
    }
}