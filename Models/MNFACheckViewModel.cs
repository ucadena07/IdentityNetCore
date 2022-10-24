using System.ComponentModel.DataAnnotations;

namespace IdentityAndSecurity.Models
{
    public class MNFACheckViewModel
    {
        [Required]
        public string Code { get; set; }
    }
}
