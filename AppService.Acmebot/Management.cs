using System;
using System.Collections.Generic;
using System.Text;

namespace AppService.Acmebot {
    using System.Net.Http;
    using System.Threading.Tasks;
    using Microsoft.Azure.WebJobs;
    using Microsoft.Azure.WebJobs.Extensions.Http;
    using Microsoft.Extensions.Logging;
    using Newtonsoft.Json;

    public class Management {
        [FunctionName(nameof(GetAllInstances))]
        public static async Task GetAllInstances(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")]
            HttpRequestMessage req,
            [OrchestrationClient] DurableOrchestrationClient client,
            ILogger log)
        {
            IList<DurableOrchestrationStatus> instances = await client.GetStatusAsync(); // You can pass CancellationToken as a parameter.
            foreach (var instance in instances)
            {
                log.LogInformation(JsonConvert.SerializeObject(instance));
            }
        }

        [FunctionName(nameof(KillAllInstances))]
        public static async Task KillAllInstances(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")]
            HttpRequestMessage req,
            [OrchestrationClient] DurableOrchestrationClient client,
            ILogger log)
        {
            IList<DurableOrchestrationStatus> instances = await client.GetStatusAsync(); // You can pass CancellationToken as a parameter.
            var tasks = new List<Task>();
            foreach (var instance in instances)
            {
                tasks.Add(client.TerminateAsync(instance.InstanceId, "kill"));
            }

            Task.WaitAll(tasks.ToArray());
        }
    }
}
