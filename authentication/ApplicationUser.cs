using Microsoft.AspNetCore.Identity;
using System;

namespace JWTAuthenticationAndAuthorization.authentication
{
    public class ApplicationUser : IdentityUser
    {
        public string VendorName { get; set; }
        public string RefreshToken { get; internal set; }
        public DateTime RefreshTokenExpiryTime { get; internal set; }
    }
}