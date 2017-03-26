#!/usr/bin/env bash
dotnet restore && dotnet build
dotnet test ./tests/AspNetCore.Identity.Elastic.Tests/AspNetCore.Identity.Elastic.Tests.csproj
