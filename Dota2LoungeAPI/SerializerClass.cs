using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SteamBotV2.Dota2LoungeAPI
{
    public class SerializerClass
    {
    }

    public class GetRsaKey
    {
        public bool success { get; set; }

        public string publickey_mod { get; set; }

        public string publickey_exp { get; set; }

        public string timestamp { get; set; }

        public string steamid { get; set; }
    }

    public class DoLoginRootObject
    {
        public bool success { get; set; }
        public bool requires_twofactor { get; set; }
        public bool login_complete { get; set; }
        public string transfer_url { get; set; }
        public TransferParameters transfer_parameters { get; set; }
    }

    public class TransferParameters
    {
        public string steamid { get; set; }
        public string token { get; set; }
        public string auth { get; set; }
        public string remember_login { get; set; }
        public string webcookie { get; set; }
        public string token_secure { get; set; }
    }
}
