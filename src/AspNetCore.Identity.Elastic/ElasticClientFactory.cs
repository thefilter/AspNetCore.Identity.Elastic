using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Nest;
using Elasticsearch.Net;
using Newtonsoft.Json;

[assembly: InternalsVisibleTo("AspNetCore.Identity.Elastic.Tests")]
namespace AspNetCore.Identity.Elastic
{    
    internal static class ElasticClientFactory
    {
        public static IElasticClient Create(Uri node, string defaultIndex)
        {
            var settings = new ConnectionSettings(
                new SingleNodeConnectionPool(node),
                new HttpConnection(),
                new SerializerFactory(DefineSerializationSettings));

            settings.MapDefaultTypeIndices(m => m
                .Add(typeof(ElasticIdentityUser), defaultIndex));

            var transport = new Transport<IConnectionSettingsValues>(settings);
            
            return new ElasticClient(settings);
        }

        private static void DefineSerializationSettings(
            JsonSerializerSettings jsonSerializerSettings,
            IConnectionSettingsValues connectionSettingsValues)
        {
            var dateTimeConverter = new UtcIsoDateTimeConverter();

            if (jsonSerializerSettings.Converters == null)
            {
                jsonSerializerSettings.Converters = new List<JsonConverter>();
            }

            jsonSerializerSettings.Converters.Add(dateTimeConverter);

            jsonSerializerSettings.DateTimeZoneHandling = DateTimeZoneHandling.Utc;
        }
    }
}
