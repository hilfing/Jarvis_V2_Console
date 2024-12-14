FROM mcr.microsoft.com/dotnet/runtime:9.0 AS base
USER $APP_UID
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["Jarvis V2 Console/Jarvis V2 Console.csproj", "Jarvis V2 Console/"]
RUN dotnet restore "Jarvis V2 Console/Jarvis V2 Console.csproj"
COPY . .
WORKDIR "/src/Jarvis V2 Console"
RUN dotnet build "Jarvis V2 Console.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "Jarvis V2 Console.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Jarvis V2 Console.dll"]
