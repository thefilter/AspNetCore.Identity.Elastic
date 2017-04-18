using System;
using System.Globalization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("AspNetCore.Identity.Elastic.Tests")]
namespace AspNetCore.Identity.Elastic
{
    internal class UtcIsoDateTimeConverter : IsoDateTimeConverter
    {
        //Since we use strict_date_time format in our elasticsearch mappings for all dates, we 
        //need to ensure that serialized dates match that format. The format defined below 
        //is based on strict_date_time in elasticsearch version 5.3.0. 
        //documentation @ https://www.elastic.co/guide/en/elasticsearch/reference/5.3/mapping-date-format.html
        public const string UTC_FORMAT = "yyyy-MM-ddTHH:mm:ss.fffffffzz";

        public UtcIsoDateTimeConverter()
        {
            //Forcibly override the datetime format with our own, as the default datetime format used in 
            //IsoDateTimeConverter uses a format () which trims the milliseconds portion of the datetime string 
            //if they're all zeroes, causing a parse failure when attempting to write to the date fields in the 
            //user index due to the strict_date_time format specified on the mapping.
            DateTimeFormat = UTC_FORMAT;
            
            //We're dealing in Utc everywhere, so assume that. This might be a failure point if that's ever 
            //not a safe assumption to make.
            DateTimeStyles = DateTimeStyles.AdjustToUniversal;
        }
        
        public override bool CanRead => true;

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            return base.ReadJson(reader, objectType, existingValue, serializer);
        }

        public override bool CanWrite => true;

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            string text;

            switch (value)
            {
                case DateTimeOffset v:
                    DateTimeOffset datetimeOffset = ((DateTimeOffset)value).ToUniversalTime();
                    text = datetimeOffset.ToString(UTC_FORMAT);
                    break;
                case DateTime v:
                    DateTime datetime = ((DateTime)value).ToUniversalTime();
                    text = datetime.ToString(UTC_FORMAT);
                    break;
                default:
                    base.WriteJson(writer, value, serializer);
                    return;
            }

            writer.WriteValue(text);
        }
    }
}