namespace JWTAuthenticationAndAuthorization.authentication
{
    public class AuthModel
    {
        public string Status { get; set; }
        public string Message { get; set; }
    }

    public class TokenModel
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }
}
