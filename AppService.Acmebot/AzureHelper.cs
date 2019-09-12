using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using ACMESharp.Authorizations;
using ACMESharp.Crypto;
using ACMESharp.Protocol;
using AppService.Acmebot.Internal;
using DnsClient;
using Microsoft.Azure.Management.Dns;
using Microsoft.Azure.Management.Dns.Models;
using Microsoft.Azure.Management.WebSites;
using Microsoft.Azure.Management.WebSites.Models;
using Microsoft.Azure.WebJobs;

namespace AppService.Acmebot
{
    public class AzureHelper
    {
        public AzureHelper(IHttpClientFactory httpClientFactory, LookupClient lookupClient, IAcmeProtocolClientFactory acmeProtocolClientFactory,
                          WebSiteManagementClient webSiteManagementClient, DnsManagementClient dnsManagementClient)
        {
            _httpClientFactory = httpClientFactory;
            _lookupClient = lookupClient;
            _acmeProtocolClientFactory = acmeProtocolClientFactory;
            _webSiteManagementClient = webSiteManagementClient;
            _dnsManagementClient = dnsManagementClient;
            AzureHelper.Instance = this;
        }

        public static AzureHelper Instance { get; private set; }

        private const string InstanceIdKey = "InstanceId";

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly LookupClient _lookupClient;
        private readonly IAcmeProtocolClientFactory _acmeProtocolClientFactory;
        private readonly WebSiteManagementClient _webSiteManagementClient;
        private readonly DnsManagementClient _dnsManagementClient;

        public async Task<Site> GetSite(string resourceGroupName, string siteName, string slotName)
        {
            if (!"production".Equals(slotName) && !string.IsNullOrEmpty(slotName))
            {
                return await _webSiteManagementClient.WebApps.GetSlotAsync(resourceGroupName, siteName, slotName);
            }

            return await _webSiteManagementClient.WebApps.GetAsync(resourceGroupName, siteName);
        }

        public async Task<IList<Site>> GetSites()
        {
            var list = new List<Site>();

            var sites = await _webSiteManagementClient.WebApps.ListAsync();

            foreach (var site in sites)
            {
                var slots = await _webSiteManagementClient.WebApps.ListSlotsAsync(site.ResourceGroup, site.Name);

                list.Add(site);
                list.AddRange(slots);
            }

            return list.Where(x => x.HostNameSslStates.Any(xs => !xs.Name.EndsWith(".azurewebsites.net") && !xs.Name.EndsWith(".trafficmanager.net"))).ToArray();
        }

        public async Task<Zone> GetZone(string dnsZoneName)
        {
            foreach (var zone in await _dnsManagementClient.Zones.ListAsync())
            {
                if (string.Equals(zone.Name, dnsZoneName, StringComparison.OrdinalIgnoreCase))
                {
                    return zone;
                }
            }

            throw new ArgumentException($"Cannot find DNS Zone {dnsZoneName}. Please check the name and IAM.");
        }


        public async Task<IList<Zone>> GetZones()
        {
            return (await _dnsManagementClient.Zones.ListAsync()).ToArray();
        }

        public async Task<IList<Certificate>> GetExpiringCertificates(DateTime currentDateTime)
        {
            var certificates = await _webSiteManagementClient.Certificates.ListAsync();
            int days;
            if (!int.TryParse(Environment.GetEnvironmentVariable("RenewDays"), out days))
            {
                days = 30;
            }

            return certificates
                   .Where(x => x.Issuer == "Let's Encrypt Authority X3" || x.Issuer == "Let's Encrypt Authority X4" || x.Issuer == "Fake LE Intermediate X1")
                   .Where(x => (x.ExpirationDate.Value - currentDateTime).TotalDays < days).ToArray();
        }

        public async Task<IList<Certificate>> GetAllCertificates()
        {
            var certificates = await _webSiteManagementClient.Certificates.ListAsync();

            return certificates.ToArray();
        }

        public async Task<DeploymentLocations> GetAllLocations()
        {
            return await this._webSiteManagementClient.GetSubscriptionDeploymentLocationsAsync();
        }

        public Task UpdateCertificate(Site site, string certificateName, byte[] pfxBlob)
        {
            SavePfx(pfxBlob, certificateName);

            return _webSiteManagementClient.Certificates.CreateOrUpdateAsync(site.ResourceGroup, certificateName, new Certificate
            {
                Location = site.Location,
                Password = "P@ssw0rd",
                PfxBlob = pfxBlob,
                ServerFarmId = site.ServerFarmId
            });
        }

        public Task UploadCertificate(string resourceGroup, string location, string certificateName, byte[] pfxBlob)
        {
            SavePfx(pfxBlob, certificateName);

            return _webSiteManagementClient.Certificates.CreateOrUpdateAsync(
                resourceGroup,
                certificateName,
                new Certificate
                {
                    Password = "P@ssw0rd",
                    PfxBlob = pfxBlob,
                    Location = location
                });
        }

        public Task UpdateSiteBinding(Site site)
        {
            return _webSiteManagementClient.WebApps.CreateOrUpdateAsync(site);
        }

        public Task DeleteCertificate(Certificate certificate)
        {
            var resourceId = ParseResourceId(certificate.Id);

            return _webSiteManagementClient.Certificates.DeleteAsync(resourceId.resourceGroup, certificate.Name);
        }

        public static (string subscription, string resourceGroup, string provider) ParseResourceId(string resourceId)
        {
            var values = resourceId.Split('/', StringSplitOptions.RemoveEmptyEntries);

            return (values[1], values[3], values[5]);
        }

        private static void SavePfx(byte[] pfxBlob, string filename)
        {
            using (var fs = new FileStream(filename, FileMode.Create))
            {
                fs.Write(pfxBlob);
            }
        }
    }
}