using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using PersonalPhotos.Contracts;

namespace PersonalPhotos.Strategies
{
	public class SmtpEmail : IEmail
	{
		private readonly EmailOptions _options;
		public SmtpEmail(IOptions<EmailOptions> options)
		{
			_options = options.Value;
		}
		public async Task Send(string emailAddress, string body)
		{
			var client = new SmtpClient();
			client.Host = _options.Host;
			client.Credentials = new NetworkCredential(_options.UserName, _options.Password);

			var message = new MailMessage("chris@joycenet.us", emailAddress);

			message.Body = body;
			message.IsBodyHtml = true;
			await client.SendMailAsync(message);
		}
	}
}
