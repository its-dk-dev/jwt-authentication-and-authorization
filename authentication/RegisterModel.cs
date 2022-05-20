using System.ComponentModel.DataAnnotations;

namespace JWTAuthenticationAndAuthorization.authentication
{
    public class RegisterModel
    {
        [Required(ErrorMessage = "Vendor Name is required")]
        public string VendorName { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }

    }
}
