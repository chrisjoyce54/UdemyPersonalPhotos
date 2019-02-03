using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;

namespace PersonalPhotos.Controllers
{
    public class ChangePasswordViewModel
    {
        [Required]
        public string EmailAddress { get; set; }
        [Required]
        [DataType((DataType.Password))]
        public string Password { get; set; }
        [Required]
        public string Token { get; set; }

        public ChangePasswordViewModel()
        {
        }
}
}