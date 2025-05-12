FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY stocktaking-auth.csproj ./
RUN dotnet restore "stocktaking-auth.csproj"

COPY . ./
RUN dotnet publish "stocktaking-auth.csproj" -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish ./

# Открываем порт 5100
EXPOSE 5100

ENTRYPOINT ["dotnet", "stocktaking-auth.dll"]
