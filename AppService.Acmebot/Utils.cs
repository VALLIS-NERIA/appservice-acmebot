using System;
using System.Collections.Generic;
using System.Text;

namespace AppService.Acmebot
{
    class Utils
    {
        public static AcmeProcess Acme { get; private set; }
        public static AzureHelper Azure { get; private set; }

        public Utils(AcmeProcess acme, AzureHelper azure)
        {
            Utils.Acme = acme;
            Utils.Azure = azure;
        }
    }
}