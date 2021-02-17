using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace TokenParser
{
    public class Parser
    {
        private readonly Encoding encoding;
        private readonly JwtSecurityTokenHandler handler;

        public Parser(bool useUTF8 = true)
        {
            encoding = useUTF8 ? Encoding.UTF8 : Encoding.ASCII;
            handler = new JwtSecurityTokenHandler();
        }

        private SymmetricSecurityKey GetKey(string keySecret)
        {
            return new SymmetricSecurityKey(encoding.GetBytes(keySecret));
        }

        public ClaimsPrincipal Parse(string keySecret, string token)
        {
            var validations = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = GetKey(keySecret),
                ValidateIssuer = false,
                ValidateAudience = false
            };
            return handler.ValidateToken(token, validations, out var tokenSecure);
        } // END Parse
    }
}
