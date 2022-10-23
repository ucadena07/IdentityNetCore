using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Mail;

namespace IdentityAndSecurity.Service
{
    public class SmtpEmailSender : IEmailSender
    {
        private readonly SmtpOptions _options;
        public SmtpEmailSender(IOptions<SmtpOptions> options)
        {
            _options = options.Value;
        }
        public async Task SendEmailAsync(string from, string to, string subject, string body)
        {
            var mailMessage = new MailMessage(from,to,subject,body);
            using (var client = new SmtpClient(_options.Host, _options.Port)
            {
                Credentials = new NetworkCredential(_options.Username, _options.Password)
            })
            {
                await client.SendMailAsync(mailMessage);
            } ;

        }
    }
}
