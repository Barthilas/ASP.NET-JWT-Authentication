using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;

namespace ASP.NET_JWT_Authentication
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var jwkString = "{\"additionalData\":{},\"alg\":null,\"crv\":null,\"d\":null,\"dp\":null,\"dq\":null,\"e\":\"AQAB\",\"k\":null,\"keyId\":null,\"keyOps\":[],\"kid\":null,\"kty\":\"RSA\",\"n\":\"1ze29efLpEQLjrfhSFnCl87fJ-aO8bphK49Mq64KOP23dcvz4l6bwrlekLan9A25pgdI2ni2lvVJh9oo5PQEaaQ_UsjhKXanRNHG0kBQ796JxbBclUQ25txLDdOgNE6jtxs1B5tniHBwPDnL7z8UC5RTFXxnl2XY7MyJkt3maOn67Q6DtHvsrQZDSkac_nbv6qEMAtUXRsVm3kjPY-7E4VryjiI1KZ6oQVu_h7pWeVVso1awzwAzQVY6rXzkPrzW54ec1ypi9TBsQpz1fBy6R2UMmpALPoAP03qA_YPmotAfo1lN6dswhsHRKoFJFnUUv8sboeEhB69B7kq64iMFiQ\",\"oth\":null,\"p\":null,\"q\":null,\"qi\":null,\"use\":null,\"x\":null,\"x5c\":[],\"x5t\":null,\"x5tS256\":null,\"x5u\":null,\"y\":null,\"keySize\":2048,\"hasPrivateKey\":false,\"cryptoProviderFactory\":{\"cryptoProviderCache\":{},\"customCryptoProvider\":null,\"cacheSignatureProviders\":true,\"signatureProviderObjectPoolCacheSize\":64}}";
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddAuthentication("jwt")
                .AddJwtBearer("jwt", o =>
                {
                    o.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateAudience = false,
                        ValidateIssuer = false
                    };

                    o.Events = new JwtBearerEvents()
                    {
                        OnMessageReceived = (ctx) =>
                        {
                            if (ctx.Request.Query.ContainsKey("t"))
                            {
                                //shortcircuit
                                ctx.Token = ctx.Request.Query["t"];
                            }
                            return Task.CompletedTask;
                        }
                    };

                    //Key roll over, dynamically resolve keys. Implement.
                    //o.ConfigurationManager

                    o.Configuration = new OpenIdConnectConfiguration()
                    {
                        SigningKeys =
                        {
                            JsonWebKey.Create(jwkString)
                        }
                    };

                    //Do not map to default "name".
                    o.MapInboundClaims = false;
                });


            var app = builder.Build();

            app.UseAuthentication();

            app.MapGet("/", (HttpContext ctx) => ctx.User.FindFirst("sub")?.Value ?? "empty");

            //Will fail as this only has public key.
            app.MapGet("/jwt", () =>
            {
                var handler = new JsonWebTokenHandler();
                var token = handler.CreateToken(new SecurityTokenDescriptor()
                {
                    Issuer = "https://localhost:5000",
                    Subject = new ClaimsIdentity(new[]
                    {
                        new Claim("sub", Guid.NewGuid().ToString()),
                        new Claim("name", "Anton"),
                    }),
                    SigningCredentials = new SigningCredentials(JsonWebKey.Create(jwkString), SecurityAlgorithms.RsaSha256)
                });
                return token;
            });

            app.Run();
        }
    }
}