namespace IdentityAndSecurity.Models
{
    public class SigninDto
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public bool RememberMe { get; set; }
    }
}
