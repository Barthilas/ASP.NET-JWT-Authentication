using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Server
{
    public class Program
    {
        public static void Main(string[] args)
        {
            //Contains both private and public key!
            var rsaKey = RSA.Create();
            rsaKey.ImportRSAPrivateKey(File.ReadAllBytes("key"), out _);


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
                            new RsaSecurityKey(rsaKey)
                        }
                    };

                    //Do not map to default "name".
                    o.MapInboundClaims = false;
                });

            var app = builder.Build();

            app.UseAuthentication();

            //https://localhost:7062/?t=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiZGRlMmU5Zi1hNmM0LTQ1ZTktYTQ5Yi1lODhiODQ4NGVmN2IiLCJuYW1lIjoiQW50b24iLCJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo1MDAwIiwiZXhwIjoxNjczMTkzMzg0LCJpYXQiOjE2NzMxODk3ODQsIm5iZiI6MTY3MzE4OTc4NH0.iJEXqYPF_Js8kZXJXLCWdtZTj5EjIQrwoJBeOlniMMfDomehaFImGpmnjbtdchY16p9b4d29uCb18WKOYwjeVNMZ6hWIBawFamtmXqh7yJl3U0MuCl6ucahB778pnY0mem2Kx4_LnRPqaxnZziFJXro9o4rF_BTWWXQ5PmsZ4LkTzyiMbqH2IlRQH_0DQ0134mL0dwnllpKL8EUfl6n9yWCtfF9oI1lgFYhi0DEUlk6w78qZlBrxtdT5KffTl3DuJCr9jyV3U0FkPnqSwGCY821heyQlpet4LHg9iVfzNofa-_NDi39NYolzjLqJBmFyREvsWDpohTXOzskueFiw6A
            app.MapGet("/", (HttpContext ctx) => ctx.User.FindFirst("sub")?.Value ?? "empty");

            app.MapGet("/jwt", () =>
            {
                var handler = new JsonWebTokenHandler();
                var key = new RsaSecurityKey(rsaKey);
                var token = handler.CreateToken(new SecurityTokenDescriptor()
                {
                    Issuer = "https://localhost:5000",
                    Subject = new ClaimsIdentity(new[]
                    {
                        new Claim("sub", Guid.NewGuid().ToString()),
                        new Claim("name", "Bart"),
                    }),
                    SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
                });
                return token;
            });

            app.MapGet("/jwk", () =>
            {
                var publicKey = RSA.Create();
                publicKey.ImportRSAPublicKey(rsaKey.ExportRSAPublicKey(), out _);

                var key = new RsaSecurityKey(publicKey);
                return JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
            });

            app.MapGet("/jwk-private", () =>
            {
                var key = new RsaSecurityKey(rsaKey);
                return JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
            });

            app.Run();
        }
    }
}