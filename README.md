# AspNetCore.Identity.Elastic

[![Build Status](https://travis-ci.org/thefilter/AspNetCore.Identity.Elastic.svg?branch=master)](https://travis-ci.org/thefilter/AspNetCore.Identity.Elastic) [![NuGet package version](https://img.shields.io/nuget/v/AspNetCore.Identity.Elastic.svg)](https://www.nuget.org/packages/AspNetCore.Identity.Elastic/)

[Elasticsearch](https://www.elastic.co/products/elasticsearch) data store adaptor for [ASP.NET Core Identity](https://github.com/aspnet/Identity).

**ATTENTION:**

This project is still in alpha stage.


## Building and developing

Either install Visual Studio 2017 which comes with the latest SDK or on Mac or Linux follow the Microsoft's [instructions](https://www.microsoft.com/net/core) on how to download and install the .NET SDK 1.1.

## Usage

This library supports [`netstandard1.4`](https://docs.microsoft.com/en-us/dotnet/articles/standard/library) and above.

### Tests

In order to run the tests, Elasticsearch must be running on `127.0.0.1:9200`.

To start Elasticsearch (and Kibana) via docker use the following command in the docker sub-directory:
```bash
docker-compose up -d
```
The Elastic and Kibana versions can be modified in the .env file, but default to 5.5.2.

The simplest way to run the tests is with the following command:
```bash
dotnet test ./tests/AspNetCore.Identity.Elastic.Tests/AspNetCore.Identity.Elastic.Tests.csproj
```

### Samples

You can find samples under the [./samples](./samples) folder.
