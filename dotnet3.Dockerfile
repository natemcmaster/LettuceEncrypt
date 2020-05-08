FROM mcr.microsoft.com/dotnet/core/aspnet:3.1 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/core/sdk:3.1 AS env
WORKDIR /src

COPY . .
RUN dotnet restore

FROM env AS publish
RUN dotnet publish test/Integration/Web/Web.csproj -c Release -o /app

FROM base AS final
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "Web.dll"]
