using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace PersonalPhotos.Models
{
    public class MfaCreateViewModel
    {
        public string AuthKey { get; set; }
        [Required(ErrorMessage = "You must enter a code")]
        public string Code { get; set; }
    }
}
