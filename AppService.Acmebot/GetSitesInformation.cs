using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using AppService.Acmebot.Internal;

using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;

using Newtonsoft.Json;

namespace AppService.Acmebot
{
    using System.Runtime.ConstrainedExecution;

    public class GetSitesInformation
    {
        [FunctionName("GetSitesInformation")]
        public async Task<IList<ResourceGroupInformation>> RunOrchestrator([OrchestrationTrigger] DurableOrchestrationContext context)
        {
            var proxy = context.CreateActivityProxy<ISharedFunctions>();

            // App Service を取得
            var sites = await proxy.GetSites();
            var certificates = await proxy.GetAllCertificates();

            var result = new List<ResourceGroupInformation>();

            foreach (var item in sites.ToLookup(x => x.ResourceGroup))
            {
                var resourceGroup = new ResourceGroupInformation
                {
                    Name = item.Key,
                    Sites = new List<SiteInformation>()
                };

                foreach (var site in item.ToLookup(x => x.SplitName().siteName))
                {
                    var siteInformation = new SiteInformation
                    {
                        Name = site.Key,
                        Slots = new List<SlotInformation>()
                    };

                    foreach (var slot in site)
                    {
                        var (_, slotName) = slot.SplitName();

                        var hostNameSslStates = slot.HostNameSslStates
                                                    .Where(x => !x.Name.EndsWith(".azurewebsites.net"));

                        var slotInformation = new SlotInformation
                        {
                            Name = slotName ?? "production",
                            Domains = hostNameSslStates.Select(x => new DomainInformation
                            {
                                Name = x.Name,
                                Issuer = certificates.FirstOrDefault(xs => xs.Thumbprint == x.Thumbprint)?.Issuer ?? "None"
                            }).ToArray()
                        };

                        if (slotInformation.Domains.Count != 0)
                        {
                            siteInformation.Slots.Add(slotInformation);
                        }
                    }

                    if (siteInformation.Slots.Count != 0)
                    {
                        resourceGroup.Sites.Add(siteInformation);
                    }
                }

                if (resourceGroup.Sites.Count != 0)
                {
                    result.Add(resourceGroup);
                }
            }

            return result;
        }

        [FunctionName("GetSitesInformation_HttpStart")]
        public async Task<HttpResponseMessage> HttpStart(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "get-sites-information")] HttpRequestMessage req,
            [OrchestrationClient] DurableOrchestrationClient starter,
            ILogger log)
        {
            if (!req.Headers.Contains("X-MS-CLIENT-PRINCIPAL-ID"))
            {
                return req.CreateErrorResponse(HttpStatusCode.Unauthorized, $"Need to activate EasyAuth.");
            }

            // Function input comes from the request content.
            var instanceId = await starter.StartNewAsync("GetSitesInformation", null);

            log.LogInformation($"Started orchestration with ID = '{instanceId}'.");

            return await starter.WaitForCompletionOrCreateCheckStatusResponseAsync(req, instanceId, TimeSpan.FromSeconds(30));
        }

        [FunctionName(nameof(GetZonesInformation))]
        public async Task<IList<string>> GetZonesInformation([OrchestrationTrigger] DurableOrchestrationContext context)
        {
            var proxy = context.CreateActivityProxy<ISharedFunctions>();
            var zones = await proxy.GetZones();

            return zones.Select(z => z.Name).ToArray();
        }

        [FunctionName(nameof(GetZonesInformation_HttpStart))]
        public async Task<HttpResponseMessage> GetZonesInformation_HttpStart(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "get-zones-information")]
            HttpRequestMessage req,
            [OrchestrationClient] DurableOrchestrationClient starter,
            ILogger log)
        {
            if (!req.Headers.Contains("X-MS-CLIENT-PRINCIPAL-ID"))
            {
                return req.CreateErrorResponse(HttpStatusCode.Unauthorized, $"Need to activate EasyAuth.");
            }

            // Function input comes from the request content.
            var instanceId = await starter.StartNewAsync(nameof(GetZonesInformation), null);

            log.LogInformation($"Started orchestration with ID = '{instanceId}'.");

            return await starter.WaitForCompletionOrCreateCheckStatusResponseAsync(req, instanceId, TimeSpan.FromSeconds(30));
        }

        [FunctionName(nameof(GetCertsInformation))]
        public async Task<IList<CertInformation>> GetCertsInformation([OrchestrationTrigger] DurableOrchestrationContext context)
        {
            var proxy = context.CreateActivityProxy<ISharedFunctions>();
            var certs = await proxy.GetAllCertificates();

            return certs.OrderByDescending(c => c.IssueDate)
                        .Select(
                            c => new CertInformation
                            {
                                HostNames = c.HostNames,
                                Thumbprint = c.Thumbprint,
                                Issuer = c.Issuer,
                                IssueDate = c.IssueDate.ToString()
                            })
                        .ToArray();
        }

        [FunctionName(nameof(GetCertsInformation_HttpStart))]
        public async Task<HttpResponseMessage> GetCertsInformation_HttpStart(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "get-certs-information")]
            HttpRequestMessage req,
            [OrchestrationClient] DurableOrchestrationClient starter,
            ILogger log)
        {
            if (!req.Headers.Contains("X-MS-CLIENT-PRINCIPAL-ID"))
            {
                return req.CreateErrorResponse(HttpStatusCode.Unauthorized, $"Need to activate EasyAuth.");
            }

            // Function input comes from the request content.
            var instanceId = await starter.StartNewAsync(nameof(GetCertsInformation), null);

            log.LogInformation($"Started orchestration with ID = '{instanceId}'.");

            return await starter.WaitForCompletionOrCreateCheckStatusResponseAsync(req, instanceId, TimeSpan.FromSeconds(30));
        }
    }

    public class ResourceGroupInformation
    {
        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("sites")]
        public IList<SiteInformation> Sites { get; set; }
    }

    public class SiteInformation
    {
        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("slots")]
        public IList<SlotInformation> Slots { get; set; }
    }

    public class SlotInformation
    {
        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("domains")]
        public IList<DomainInformation> Domains { get; set; }
    }

    public class DomainInformation
    {
        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("issuer")]
        public string Issuer { get; set; }
    }

    public class CertInformation 
    {
        [JsonProperty("hostNames")]
        public IList<string> HostNames { get; set; }

        [JsonProperty("thumbprint")]
        public string Thumbprint { get; set; }

        [JsonProperty("issuer")]
        public string Issuer { get; set; }

        [JsonProperty("issueDate")]
        public string IssueDate { get; set; }
    }
}