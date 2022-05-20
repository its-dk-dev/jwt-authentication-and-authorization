using System.ComponentModel.DataAnnotations;

namespace JWTAuthenticationAndAuthorization.authentication
{
    public class LoginModel
    {
        [Required(ErrorMessage = "Email Id is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }
    }
}