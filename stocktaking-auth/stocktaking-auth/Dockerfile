FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY ["stocktaking-auth.csproj", "./"]
RUN dotnet restore "stocktaking-auth.csproj"

COPY . .
RUN dotnet build "stocktaking-auth.csproj" -c Release -o /app/build

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app
COPY --from=build /app/build .

ENTRYPOINT ["dotnet", "stocktaking-auth.dll"]
