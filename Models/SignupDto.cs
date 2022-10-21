using System.ComponentModel.DataAnnotations;

namespace IdentityAndSecurity.Models
{
    public class SignupDto
    {
        [Required]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
