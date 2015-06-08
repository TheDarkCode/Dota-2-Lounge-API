using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using SteamBotV2.Dota2LoungeAPI;

namespace SteamBotV2
{
    class Program
    {
        static void Main(string[] args)
        {
            Login l = new Login();
			l.doLogin("steamUsername", "steamPassword");
            l.doLogin("steamUsername", "steamPassword", "gmailAddress", "gmailPassword");
            Console.ReadKey();
        }
    }
}