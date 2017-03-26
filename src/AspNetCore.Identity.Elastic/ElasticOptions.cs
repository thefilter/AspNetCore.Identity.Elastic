namespace AspNetCore.Identity.Elastic
{
    public class ElasticOptions
    {
        private const int DEFAULT_QUERY_SIZE = 10000;
        private const int NUMBER_OF_SHARDS = 1;
        private const int NUMBER_OF_REPLICAS = 1;
        private const string DEFAULT_INDEX_NAME = "users";
        private const string USER_DOC_TYPE = "identity_user";

        public string IndexName { get; set; } = DEFAULT_INDEX_NAME;
        public string UserDocType { get; set; } = USER_DOC_TYPE;
        public int QuerySize { get; set; } = DEFAULT_QUERY_SIZE;
        public int NumberOfShards { get; set; } = NUMBER_OF_SHARDS;
        public int NumberOfReplicas { get; set; } = NUMBER_OF_REPLICAS;
    }
}
