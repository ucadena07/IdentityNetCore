namespace IdentityAndSecurity.Service
{
    public class SmtpOptions
    {
        public string Host { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Domain { get; set; }
        public int Port { get; set; }
    }
}
