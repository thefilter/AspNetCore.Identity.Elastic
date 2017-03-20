using System;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.Elastic
{
    public class ElasticIdentityUserLogin : ElasticIdentityUserLogin<string>
    {
        public ElasticIdentityUserLogin(string loginProvider, string providerKey, string displayName) : base(loginProvider, providerKey, displayName)
        {
        }
    }

    public class ElasticIdentityUserLogin<TKey>: IEquatable<ElasticIdentityUserLogin<TKey>>, IEquatable<UserLoginInfo>
        where TKey : IEquatable<TKey>
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

        public bool Equals(ElasticIdentityUserLogin<TKey> other)
        {
            return other.LoginProvider.Equals(LoginProvider)
                && other.ProviderKey.Equals(ProviderKey);
        }

        public bool Equals(UserLoginInfo other)
        {
            return other.LoginProvider.Equals(LoginProvider)
                && other.ProviderKey.Equals(ProviderKey);
        }

        public static ElasticIdentityUserLogin<TKey> FromUserLoginInfo(UserLoginInfo userLoginInfo)
        {
            return new ElasticIdentityUserLogin<TKey>(userLoginInfo.LoginProvider, userLoginInfo.ProviderKey, userLoginInfo.ProviderDisplayName);
        }
    }
}