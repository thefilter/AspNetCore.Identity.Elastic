using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.CompilerServices;
using Nest;
using Elasticsearch.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

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
            //Since we use strict_date_time format in our elasticsearch mappings for all dates, we 
            //need to ensure that serialized dates match that format. The format defined below 
            //is based on strict_date_time in elasticsearch version 5.3.0. 
            //documentation @ https://www.elastic.co/guide/en/elasticsearch/reference/5.3/mapping-date-format.html
            var dateTimeConverter = new IsoDateTimeConverter
            {
                DateTimeFormat = "yyyy-MM-ddTHH:mm:ss.fffZ",
                DateTimeStyles = DateTimeStyles.AdjustToUniversal
            };

            if (jsonSerializerSettings.Converters == null)
            {
                jsonSerializerSettings.Converters = new List<JsonConverter>();
            }

            jsonSerializerSettings.Converters.Add(dateTimeConverter);
        }
    }
}
