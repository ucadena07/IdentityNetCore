using System.ComponentModel.DataAnnotations;

namespace IdentityAndSecurity.Models
{
    public class MFADto
    {
        [Required]
        public string Token { get; set; }
        [Required]
        public string Code { get; set; }
    }
}
